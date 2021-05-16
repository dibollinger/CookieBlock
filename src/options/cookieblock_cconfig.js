

const setupConfigPage = function() {
    setStaticLocaleText("cconfig-title", "extensionName");
    setStaticLocaleText("cconfig-subtitle", "cookieConfigSubtitle");
    setStaticLocaleText("cconfig-desc-title", "cookieConfigDescTitle");
    setStaticLocaleText("cconfig-desc-pg1", "cookieConfigDescPG1");
    setStaticLocaleText("cconfig-desc-pg2", "cookieConfigDescPG2");
    setStaticLocaleText("cconfig-list-title", "cookieConfigListTitle");
    setStaticLocaleText("cconfig-expand-desc", "configExpandDesc");
    setStaticLocaleText("export-button", "configExportButton");
    setStaticLocaleText("li-no-cookies", "configNoCookies");

}


document.addEventListener("DOMContentLoaded", setupConfigPage);
