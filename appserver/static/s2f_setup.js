require(["jquery", "splunkjs/mvc", "splunkjs/mvc/simplexml/ready!"], function($, mvc) {
    "use strict";

    var service = mvc.createService({ owner: "nobody", app: "TA-splunk_to_fusion" });
    // No leading slash: SplunkJS prefixes /servicesNS/<owner>/<app>/ so the
    // request lands in this app's namespace instead of the global /services.
    var ENDPOINT = "ta_s2f/broker";
    var lastCid = "default";

    function showBanner(msg, isError, isWarning) {
        var bg = isError ? "#f8d7da" : (isWarning ? "#fff3cd" : "#d4edda");
        var fg = isError ? "#721c24" : (isWarning ? "#856404" : "#155724");
        var border = isError ? "1px solid #f5c6cb" : (isWarning ? "1px solid #ffeeba" : "1px solid #c3e6cb");
        $("#s2f_status_banner").text(msg).css({
            "background-color": bg,
            "color": fg,
            "border": border
        }).show();
    }

    // SplunkJS may hand back a parsed object, a JSON string, or raw text.
    function asObject(data) {
        if (typeof data === "string") {
            try { return JSON.parse(data); } catch (e) { return {}; }
        }
        return data || {};
    }

    function messageFrom(data) {
        data = asObject(data);
        if (data.error) return data.error;
        if (data.message) return data.message;
        if (data.messages && data.messages.length) return data.messages.join(" ");
        return "";
    }

    function collectForm(opName) {
        var data = { op: opName, cid: ($("#s2f_cid_name").val() || "").trim() || "default" };
        $("[data-field]").each(function() {
            data[$(this).attr("data-field")] = ($(this).val() || "").trim();
        });
        return JSON.stringify(data);
    }

    function clearForm() {
        $("[data-field]").each(function() { $(this).val(""); });
        $("#s2f_secret_badge").text("");
        $("#s2f_hec_badge").text("");
    }

    function loadCid(name) {
        service.request(ENDPOINT, "POST", { output_mode: "json" }, JSON.stringify({ op: "get_cid", cid: name }), { "Content-Type": "application/json" }, function(err, resp) {
            var c = (resp && resp.data && resp.data.config) || {};
            $("[data-field]").each(function() {
                var key = $(this).attr("data-field");
                $(this).val(c[key] || "");
            });
            $("#s2f_secret_badge").text(c.has_client_secret ? "(Encrypted secret stored)" : "");
            $("#s2f_hec_badge").text(c.has_hec_token ? "(Encrypted token stored)" : "");
        });
    }

    function selectTenant(name) {
        lastCid = name;
        $("#s2f_cid_name").val(name);
        loadCid(name);
    }

    function createTenant() {
        var name = (window.prompt("New tenant name (used as the alert action's cid):", "") || "").trim();
        if (!name || name === "__new__") {
            $("#s2f_cid_name").val(lastCid);
            return;
        }
        var exists = $("#s2f_cid_name option").filter(function() { return this.value === name; }).length > 0;
        if (exists) {
            return selectTenant(name);
        }
        $("#s2f_cid_name option[value='__new__']").before($("<option>").val(name).text(name));
        lastCid = name;
        $("#s2f_cid_name").val(name);
        clearForm();
    }

    $("#s2f_cid_name").on("change", function() {
        var name = $(this).val();
        if (name === "__new__") {
            return createTenant();
        }
        selectTenant(name);
    });

    $("#s2f_btn_save").on("click", function() {
        service.request(ENDPOINT, "POST", { output_mode: "json" }, collectForm("save_cid"), { "Content-Type": "application/json" }, function(err, resp) {
            if (err) {
                return showBanner(messageFrom((err && (err.data || err.responseText))) || "Failed to save configuration.", true);
            }
            $("[type=password]").val("");
            showBanner(messageFrom(resp && resp.data) || "Configuration saved.", false);
            loadCid(lastCid);
        });
    });

    $("#s2f_btn_test").on("click", function() {
        showBanner("Testing OAuth2 connection to CrowdStrike...", false);
        service.request(ENDPOINT, "POST", { output_mode: "json" }, collectForm("test_connection"), { "Content-Type": "application/json" }, function(err, resp) {
            if (err) {
                return showBanner(messageFrom((err && (err.data || err.responseText))) ||
                    "Connection test failed. See the Splunk log for details.", true);
            }
            var data = asObject(resp && resp.data);
            var warnings = data.warnings || [];
            var message = data.message || "Connection succeeded.";
            showBanner(warnings.length ? message + " " + warnings.join(" ") : message, false, warnings.length > 0);
        });
    });

    service.request(ENDPOINT, "POST", { output_mode: "json" }, JSON.stringify({ op: "get_cids" }), { "Content-Type": "application/json" }, function(err, resp) {
        var cids = (resp && resp.data && resp.data.cids) || ["default"];
        var $select = $("#s2f_cid_name").empty();
        cids.forEach(function(cid) {
            $select.append($("<option>").val(cid).text(cid));
        });
        $select.append($("<option>").val("__new__").text("+ New tenant…"));
        selectTenant(cids[0] || "default");
    });
});
