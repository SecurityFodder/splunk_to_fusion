require(["jquery", "splunkjs/mvc", "splunkjs/mvc/simplexml/ready!"], function($, mvc) {
    "use strict";

    var service = mvc.createService({ owner: "nobody", app: "TA-splunk_to_fusion" });
    var ENDPOINT = "/services/ta_s2f/broker";

    function showBanner(msg, isError) {
        $("#s2f_status_banner").text(msg).css({
            "background-color": isError ? "#f8d7da" : "#d4edda",
            "color": isError ? "#721c24" : "#155724",
            "border": isError ? "1px solid #f5c6cb" : "1px solid #c3e6cb"
        }).show();
    }

    function collectForm(opName) {
        var data = { op: opName };
        $("[data-field]").each(function() {
            data[$(this).attr("data-field")] = ($(this).val() || "").trim();
        });
        return JSON.stringify(data);
    }

    function loadConfig() {
        service.request(ENDPOINT, "GET", { output_mode: "json" }, null, null, { "Content-Type": "application/json" }, function(err, resp) {
            var c = (resp && resp.data && resp.data.config) || {};
            $("[data-field]").each(function() {
                var key = $(this).attr("data-field");
                if (c[key]) { $(this).val(c[key]); }
            });
            $("#s2f_secret_badge").text(c.has_client_secret ? "(Encrypted secret stored)" : "");
            $("#s2f_hec_badge").text(c.has_hec_token ? "(Encrypted token stored)" : "");
        });
    }

    $("#s2f_btn_save").on("click", function() {
        service.request(ENDPOINT, "POST", { output_mode: "json" }, collectForm("save_config"), { "Content-Type": "application/json" }, function(err, resp) {
            if (err) {
                return showBanner((err.data && err.data.error) || "Failed to save configuration.", true);
            }
            $("[type=password]").val("");
            showBanner((resp && resp.data && resp.data.message) || "Configuration saved.", false);
            loadConfig();
        });
    });

    $("#s2f_btn_test").on("click", function() {
        showBanner("Testing OAuth2 connection to CrowdStrike...", false);
        service.request(ENDPOINT, "POST", { output_mode: "json" }, collectForm("test_connection"), { "Content-Type": "application/json" }, function(err, resp) {
            if (err) {
                return showBanner((err.data && err.data.error) || "Connection test failed.", true);
            }
            showBanner((resp && resp.data && resp.data.message) || "Connection succeeded.", false);
        });
    });

    loadConfig();
});
