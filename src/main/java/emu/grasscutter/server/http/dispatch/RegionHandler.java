package emu.grasscutter.server.http.dispatch;

import com.google.protobuf.ByteString;
import emu.grasscutter.GameConstants;
import emu.grasscutter.Grasscutter;
import emu.grasscutter.Grasscutter.ServerRunMode;
import emu.grasscutter.net.proto.QueryRegionListHttpRspOuterClass.QueryRegionListHttpRsp;
import emu.grasscutter.net.proto.QueryCurrRegionHttpRspOuterClass.QueryCurrRegionHttpRsp;
import emu.grasscutter.net.proto.RegionSimpleInfoOuterClass.RegionSimpleInfo;
import emu.grasscutter.net.proto.RegionInfoOuterClass.RegionInfo;
import emu.grasscutter.net.proto.ResVersionConfigOuterClass.ResVersionConfig;
import emu.grasscutter.net.proto.PlatformTypeOuterClass.PlatformType;
import emu.grasscutter.net.proto.RetcodeOuterClass.Retcode;
import emu.grasscutter.net.proto.StopServerInfoOuterClass.StopServerInfo;
import emu.grasscutter.server.event.dispatch.QueryAllRegionsEvent;
import emu.grasscutter.server.event.dispatch.QueryCurrentRegionEvent;
import emu.grasscutter.server.http.Router;
import emu.grasscutter.server.http.objects.QueryCurRegionRspJson;
import emu.grasscutter.utils.Crypto;
import emu.grasscutter.utils.Utils;
import io.javalin.Javalin;
import io.javalin.http.Context;

import java.time.Instant;
import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.security.Signature;
import java.util.regex.Pattern;

import static emu.grasscutter.config.Configuration.*;

/**
 * Handles requests related to region queries.
 */
public final class RegionHandler implements Router {
    private static final Map<String, RegionData> regions = new ConcurrentHashMap<>();
    private static String regionListResponse;

    public RegionHandler() {
        try { // Read & initialize region data.
            this.initialize();
        } catch (Exception exception) {
            Grasscutter.getLogger().error("Failed to initialize region data.", exception);
        }
    }

    /**
     * Configures region data according to configuration.
     */
    private void initialize() {
        String dispatchDomain = "http" + (HTTP_ENCRYPTION.useInRouting ? "s" : "") + "://"
            + lr(HTTP_INFO.accessAddress, HTTP_INFO.bindAddress) + ":"
            + lr(HTTP_INFO.accessPort, HTTP_INFO.bindPort);

        // Create regions.
        List<RegionSimpleInfo> servers = new ArrayList<>();
        List<String> usedNames = new ArrayList<>(); // List to check for potential naming conflicts.

        var configuredRegions = new ArrayList<>(List.of(DISPATCH_INFO.regions));
        if (SERVER.runMode != ServerRunMode.HYBRID && configuredRegions.size() == 0) {
            Grasscutter.getLogger().error("[Dispatch] There are no game servers available. Exiting due to unplayable state.");
            System.exit(1);
        } else if (configuredRegions.size() == 0)
            configuredRegions.add(new Region("os_usa", DISPATCH_INFO.defaultName,
                lr(GAME_INFO.accessAddress, GAME_INFO.bindAddress),
                lr(GAME_INFO.accessPort, GAME_INFO.bindPort)));

        configuredRegions.forEach(region -> {
            if (usedNames.contains(region.Name)) {
                Grasscutter.getLogger().error("Region name already in use.");
                return;
            }

            // Create a region identifier.
            var identifier = RegionSimpleInfo.newBuilder()
                .setName(region.Name).setTitle(region.Title).setType("DEV_PUBLIC")
                .setDispatchUrl(dispatchDomain + "/query_cur_region/" + region.Name)
                .build();
            usedNames.add(region.Name);
            servers.add(identifier);

            // Create a region info object.
            var regionInfo = RegionInfo.newBuilder()
                .setGateserverIp(region.Ip).setGateserverPort(region.Port)
                .setSecretKey(ByteString.copyFrom(Crypto.DISPATCH_SEED))

                .build();
            // Create an updated region query.
            var updatedQuery = QueryCurrRegionHttpRsp.newBuilder().setRegionInfo(regionInfo).build();
            regions.put(region.Name, new RegionData(updatedQuery, Utils.base64Encode(updatedQuery.toByteString().toByteArray())));
        });

        // Create a config object.
        byte[] customConfig = "{\"sdkenv\":\"2\",\"checkdevice\":\"false\",\"loadPatch\":\"false\",\"showexception\":\"false\",\"regionConfig\":\"pm|fk|add\",\"downloadMode\":\"0\"}".getBytes();
        Crypto.xor(customConfig, Crypto.DISPATCH_KEY); // XOR the config with the key.

        // Create an updated region list.
        QueryRegionListHttpRsp updatedRegionList = QueryRegionListHttpRsp.newBuilder()
            .addAllRegionList(servers)
            .setClientSecretKey(ByteString.copyFrom(Crypto.DISPATCH_SEED))
            .setClientCustomConfigEncrypted(ByteString.copyFrom(customConfig))
            .setEnableLoginPc(true).build();

        // Set the region list response.
        regionListResponse = Utils.base64Encode(updatedRegionList.toByteString().toByteArray());
    }

    @Override
    public void applyRoutes(Javalin javalin) {
        javalin.get("/query_region_list", RegionHandler::queryRegionList);
        javalin.get("/query_cur_region/{region}", RegionHandler::queryCurrentRegion);
    }

    /**
     * @route /query_region_list
     */
    private static void queryRegionList(Context ctx) {
        // Invoke event.
        QueryAllRegionsEvent event = new QueryAllRegionsEvent(regionListResponse);
        event.call();
        // Respond with event result.
        ctx.result(event.getRegionList());

        // Log to console.
        Grasscutter.getLogger().info(String.format("[Dispatch] Client %s request: query_region_list", ctx.ip()));
    }

    /**
     * @route /query_cur_region/{region}
     */
    private static void queryCurrentRegion(Context ctx) {
        // Get region to query.
        String regionName = ctx.pathParam("region");
        String versionName = ctx.queryParam("version");
        String platformName = ctx.queryParam("platform");  // This returns an integer. See PlatformType.proto for details.

        String clientVersion = versionName.replaceAll(Pattern.compile("[a-zA-Z]").pattern(), "");
        String[] versionCode = clientVersion.split("\\.");
        int versionMajor = Integer.parseInt(versionCode[0]);
        int versionMinor = Integer.parseInt(versionCode[1]);
        int versionFix = Integer.parseInt(versionCode[2]);

        var region = regions.get(regionName);
        if (DISPATCH_INFO.enableHotfix && versionFix < 50 && GameConstants.VERSION_FIX < 50) {  // Neither client nor server is a beta version
            region = addHotfixInfo(region, platformName);
        }

        // Get region data.
        String regionData = "CAESGE5vdCBGb3VuZCB2ZXJzaW9uIGNvbmZpZw==";
        if (ctx.queryParamMap().values().size() > 0) {
            if (region != null)
                regionData = region.getBase64();
        }

        if (versionMajor >= 3 || (versionMajor == 2 && versionMinor == 7 && versionFix >= 50) || (versionMajor == 2 && versionMinor == 8)) {
            try {
                QueryCurrentRegionEvent event = new QueryCurrentRegionEvent(regionData);
                event.call();

                String key_id = ctx.queryParam("key_id");

                // if (!clientVersion.equals(GameConstants.VERSION)) { // Reject clients when there is a version mismatch
                if (!(versionMajor == GameConstants.VERSION_MAJOR && versionMinor == GameConstants.VERSION_MINOR)) {
                    boolean updateClient = GameConstants.VERSION.compareTo(clientVersion) > 0;

                    QueryCurrRegionHttpRsp rsp =
                            QueryCurrRegionHttpRsp.newBuilder()
                                    .setRetcode(Retcode.RET_STOP_SERVER_VALUE)
                                    .setMsg("Connection Failed!")
                                    .setRegionInfo(RegionInfo.newBuilder())
                                    .setStopServer(
                                            StopServerInfo.newBuilder()
                                                    .setUrl("https://discord.gg/grasscutters")
                                                    .setStopBeginTime((int) Instant.now().getEpochSecond())
                                                    .setStopEndTime((int) Instant.now().getEpochSecond() * 2)
                                                    .setContentMsg(
                                                            updateClient
                                                                    ? "\nVersion mismatch outdated client! \n\nServer version: %s\nClient version: %s"
                                                                            .formatted(GameConstants.VERSION, clientVersion)
                                                                    : "\nVersion mismatch outdated server! \n\nServer version: %s\nClient version: %s"
                                                                            .formatted(GameConstants.VERSION, clientVersion))
                                                    .build())
                                    .buildPartial();

                    Grasscutter.getLogger().info(String.format("Connection denied for %s due to %s", ctx.ip(), updateClient ? "outdated client!" : "outdated server!"));

                    ctx.json(Crypto.encryptAndSignRegionData(rsp.toByteArray(), key_id));
                    return;
                }

                if (ctx.queryParam("dispatchSeed") == null) {
                    // More love for UA Patch players
                    var rsp = new QueryCurRegionRspJson();

                    rsp.content = event.getRegionInfo();
                    rsp.sign = "TW9yZSBsb3ZlIGZvciBVQSBQYXRjaCBwbGF5ZXJz";

                    ctx.json(rsp);
                    return;
                }


                var regionInfo = Utils.base64Decode(event.getRegionInfo());

                ctx.json(Crypto.encryptAndSignRegionData(regionInfo, key_id));
            } catch (Exception e) {
                Grasscutter.getLogger().error("An error occurred while handling query_cur_region.", e);
            }
        } else {
            // Invoke event.
            QueryCurrentRegionEvent event = new QueryCurrentRegionEvent(regionData);
            event.call();
            // Respond with event result.
            ctx.result(event.getRegionInfo());
        }
        // Log to console.
        Grasscutter.getLogger().info(String.format("Client %s request: query_cur_region/%s", ctx.ip(), regionName));
    }

    /**
     * Region data container.
     */
    public static class RegionData {
        private final QueryCurrRegionHttpRsp regionQuery;
        private final String base64;

        public RegionData(QueryCurrRegionHttpRsp prq, String b64) {
            this.regionQuery = prq;
            this.base64 = b64;
        }

        public QueryCurrRegionHttpRsp getRegionQuery() {
            return this.regionQuery;
        }

        public String getBase64() {
            return this.base64;
        }
    }

    /**
     * Gets the current region query.
     *
     * @return A {@link QueryCurrRegionHttpRsp} object.
     */
    public static QueryCurrRegionHttpRsp getCurrentRegion() {
        return SERVER.runMode == ServerRunMode.HYBRID ? regions.get("os_usa").getRegionQuery() : null;
    }

    private static RegionData addHotfixInfo(RegionData region, String platform) {
        var ip = region.regionQuery.getRegionInfo().getGateserverIp();
        var port = region.regionQuery.getRegionInfo().getGateserverPort();
        var regionInfo = RegionInfo.newBuilder()
            .setGateserverIp(ip).setGateserverPort(port)
            .setSecretKey(ByteString.copyFrom(Crypto.DISPATCH_SEED));
        switch (Integer.parseInt(platform)) {
            case PlatformType.PLATFORM_TYPE_PC_VALUE -> regionInfo
                .setAreaType("CN")
                .setResourceUrl("https://autopatchcn.yuanshen.com/client_game_res/4.0_live")
                .setDataUrl("https://autopatchcn.yuanshen.com/client_design_data/4.0_live")
                .setResourceUrlBak("4.0_live")
                .setDataUrlBak("4.0_live")
                .setClientDataVersion(17476732)
                .setClientSilenceDataVersion(17331021)
                .setClientDataMd5("""{\"remoteName\": \"data_versions\", \"md5\": \"1e79fc101f28ba17796481603e923084\", \"fileSize\": 5148}""")
                .setClientSilenceDataMd5("""{\"remoteName\": \"data_versions\", \"md5\": \"f6287b67d005680a2b032a7a6ffa4276\", \"fileSize\": 410}""")
                .setClientVersionSuffix("50c9f341ea")
                .setClientSilenceVersionSuffix("d455244a33")
                .setResVersionConfig(ResVersionConfig.newBuilder()
                    .setRelogin(false)
                    .setMd5("""{\"remoteName\": \"res_versions_external\", \"md5\": \"c77dffbd78f162f6ace0bde51dcc3526\", \"fileSize\": 1307291}\r\n{\"remoteName\": \"res_versions_medium\", \"md5\": \"102e33d3966ce9cc71c3e979cab54ff6\", \"fileSize\": 214430}\r\n{\"remoteName\": \"res_versions_streaming\", \"md5\": \"866fac5f8ce676dad0786d64a56c522b\", \"fileSize\": 85013}\r\n{\"remoteName\": \"base_revision\", \"md5\": \"7c0a3453e69c4f308a04df3520dfc92a\", \"fileSize\": 19}""")
                    .setVersion(17445512)
                    .setReleaseTotalSize("0")
                    .setVersionSuffix("53a0fc142e")
                    .setBranch("4.0_live")
                    .build());

            case PlatformType.PLATFORM_TYPE_ANDROID_VALUE ->  regionInfo
                .setAreaType("OS")
                .setResourceUrl("https://autopatchcn.yuanshen.com/client_game_res/4.0_live")
                .setDataUrl("https://autopatchcn.yuanshen.com/client_design_data/4.0_live")
                .setResourceUrlBak("4.0_live")
                .setDataUrlBak("4.0_live")
                .setClientDataVersion(17476732)
                .setClientSilenceDataVersion(17331021)
                .setClientDataMd5("""{\"remoteName\": \"data_versions\", \"md5\": \"1e79fc101f28ba17796481603e923084\", \"fileSize\": 5148}""")
                .setClientSilenceDataMd5("""{\"remoteName\": \"data_versions\", \"md5\": \"f6287b67d005680a2b032a7a6ffa4276\", \"fileSize\": 410}""")
                .setClientVersionSuffix("50c9f341ea")
                .setClientSilenceVersionSuffix("d455244a33")
                .setResVersionConfig(ResVersionConfig.newBuilder()
                    .setRelogin(false)
                    .setMd5("""{\"remoteName\": \"res_versions_external\", \"md5\": \"d8c628461baa1a9574ef32ee6b19d485\", \"fileSize\": 499387}\r\n{\"remoteName\": \"res_versions_medium\", \"md5\": \"21e31b93ce485a4ecc7d29daf59e8fa6\", \"fileSize\": 57798}\r\n{\"remoteName\": \"res_versions_streaming\", \"md5\": \"668561402c7a8d42a5aeea7f8e8dfaed\", \"fileSize\": 2124}\r\n{\"remoteName\": \"base_revision\", \"md5\": \"7c0a3453e69c4f308a04df3520dfc92a\", \"fileSize\": 19}""")
                    .setVersion(17445512)
                    .setReleaseTotalSize("0")
                    .setVersionSuffix("53a0fc142e")
                    .setBranch("4.0_live")
                    .build());

            case PlatformType.PLATFORM_TYPE_IOS_VALUE ->  regionInfo
                .setAreaType("OS")
                .setResourceUrl("https://autopatchcn.yuanshen.com/client_game_res/4.0_live")
                .setDataUrl("https://autopatchcn.yuanshen.com/client_design_data/4.0_live")
                .setResourceUrlBak("4.0_live")
                .setDataUrlBak("4.0_live")
                .setClientDataVersion(17476732)
                .setClientSilenceDataVersion(17331021)
                .setClientDataMd5("""{\"remoteName\": \"data_versions\", \"md5\": \"1e79fc101f28ba17796481603e923084\", \"fileSize\": 5148}""")
                .setClientSilenceDataMd5("""{\"remoteName\": \"data_versions\", \"md5\": \"f6287b67d005680a2b032a7a6ffa4276\", \"fileSize\": 410}""")
                .setClientVersionSuffix("50c9f341ea")
                .setClientSilenceVersionSuffix("d455244a33")
                .setResVersionConfig(ResVersionConfig.newBuilder()
                    .setRelogin(false)
                    .setMd5("""{\"remoteName\": \"res_versions_external\", \"md5\": \"8d69de6a18ccf0340e613e14d4e9573d\", \"fileSize\": 491949}\r\n{\"remoteName\": \"res_versions_medium\", \"md5\": \"e2db577d86f68e1c82956ee47cfae7e8\", \"fileSize\": 78234}\r\n{\"remoteName\": \"res_versions_streaming\", \"md5\": \"9731e89439a47afba0b565b1e8d1a8b0\", \"fileSize\": 29143}\r\n{\"remoteName\": \"base_revision\", \"md5\": \"7c0a3453e69c4f308a04df3520dfc92a\", \"fileSize\": 19}""")
                    .setVersion(17445512)
                    .setReleaseTotalSize("0")
                    .setVersionSuffix("53a0fc142e")
                    .setBranch("4.0_live")
                    .build());

            default ->  regionInfo
                .setAreaType("OS")
                .setResourceUrl("https://autopatchcn.yuanshen.com/client_game_res/4.0_live")
                .setDataUrl("https://autopatchcn.yuanshen.com/client_design_data/4.0_live")
                .setResourceUrlBak("4.0_live")
                .setDataUrlBak("4.0_live")
                .setClientDataVersion(17476732)
                .setClientSilenceDataVersion(17331021)
                .setClientDataMd5("""{\"remoteName\": \"data_versions\", \"md5\": \"1e79fc101f28ba17796481603e923084\", \"fileSize\": 5148}""")
                .setClientSilenceDataMd5("""{\"remoteName\": \"data_versions\", \"md5\": \"f6287b67d005680a2b032a7a6ffa4276\", \"fileSize\": 410}""")
                .setClientVersionSuffix("50c9f341ea")
                .setClientSilenceVersionSuffix("d455244a33")
                .setResVersionConfig(ResVersionConfig.newBuilder()
                    .setRelogin(false)
                    .setMd5("""{\"remoteName\": \"res_versions_external\", \"md5\": \"d8c628461baa1a9574ef32ee6b19d485\", \"fileSize\": 499387}\r\n{\"remoteName\": \"res_versions_medium\", \"md5\": \"21e31b93ce485a4ecc7d29daf59e8fa6\", \"fileSize\": 57798}\r\n{\"remoteName\": \"res_versions_streaming\", \"md5\": \"668561402c7a8d42a5aeea7f8e8dfaed\", \"fileSize\": 2124}\r\n{\"remoteName\": \"base_revision\", \"md5\": \"7c0a3453e69c4f308a04df3520dfc92a\", \"fileSize\": 19}""")
                    .setVersion(17445512)
                    .setReleaseTotalSize("0")
                    .setVersionSuffix("53a0fc142e")
                    .setBranch("4.0_live")
                    .build());
        }

        var updatedQuery = QueryCurrRegionHttpRsp.newBuilder().setRegionInfo(regionInfo.build()).build();
        return new RegionData(updatedQuery, Utils.base64Encode(updatedQuery.toByteString().toByteArray()));
    }
}
