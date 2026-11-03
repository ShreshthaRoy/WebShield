const tabAnalysis = {};
const tabResults = {};
const lastPageSignatures = {};
const lastNotificationLevels = {};

console.log("WebShield extension loaded successfully");


// ======================================================
// INTERNAL PAGE CHECK
// ======================================================

function isInternalPage(url) {
    if (!url) {
        return true;
    }

    return (
        url.startsWith("chrome://") ||
        url.startsWith("chrome-extension://") ||
        url.startsWith("edge://") ||
        url.startsWith("about:") ||
        url.startsWith("devtools://")
    );
}


// ======================================================
// PAGE LOAD
// ======================================================

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status !== "complete") {
        return;
    }

    const url = tab.url;

    console.log("======================================");
    console.log("TAB LOADED:", url);
    console.log("TAB ID:", tabId);
    console.log("======================================");

    if (isInternalPage(url)) {
        console.log("Skipping internal page:", url);
        return;
    }

    delete tabAnalysis[tabId];
    delete tabResults[tabId];
    delete lastPageSignatures[tabId];
    delete lastNotificationLevels[tabId];

    // Content scripts normally exist by document_idle. A delayed
    // request is kept for pages that build their DOM dynamically.
    requestPageAnalysis(tabId);

    setTimeout(() => {
        requestPageAnalysis(tabId);
    }, 1000);
});


// ======================================================
// REQUEST PAGE ANALYSIS
// ======================================================

function requestPageAnalysis(tabId) {
    chrome.tabs.sendMessage(
        tabId,
        {
            type: "REQUEST_PAGE_ANALYSIS"
        },
        response => {
            if (chrome.runtime.lastError) {
                console.log(
                    "Content script not ready for tab",
                    tabId,
                    ":",
                    chrome.runtime.lastError.message
                );
                return;
            }

            console.log(
                "Content script responded:",
                response
            );
        }
    );
}


// ======================================================
// RECEIVE MESSAGES
// ======================================================

chrome.runtime.onMessage.addListener(
    (message, sender, sendResponse) => {

        // ==================================================
        // PAGE ANALYSIS
        // ==================================================

        if (message.type === "PAGE_ANALYSIS") {
            if (!sender.tab || !sender.tab.id) {
                console.log(
                    "PAGE_ANALYSIS has no valid tab"
                );
                return;
            }

            const tabId = sender.tab.id;
            const pageData = message.data || {};
            const actualTabUrl = sender.tab.url;

            console.log("======================================");
            console.log("PAGE ANALYSIS RECEIVED:");
            console.log(pageData);
            console.log("TAB ID:", tabId);
            console.log("ACTUAL TAB URL:", actualTabUrl);
            console.log("PAGE DATA URL:", pageData.url);

            if (isInternalPage(actualTabUrl)) {
                console.log(
                    "Ignoring analysis from internal page:",
                    actualTabUrl
                );
                return;
            }

            tabAnalysis[tabId] = pageData;

            console.log(
                "STORED ANALYSIS FOR TAB:",
                tabId
            );

            // Avoid sending identical page analyses to Flask.
            // This removes duplicate requests/notifications while
            // still allowing genuinely changed DOM data through.
            const signature = JSON.stringify({
                url: actualTabUrl,
                title: pageData.title || "",
                forms: pageData.forms || 0,
                password_fields: pageData.password_fields || 0,
                iframes: pageData.iframes || 0,
                external_links: pageData.external_links || 0,
                external_form_actions:
                    pageData.external_form_actions || 0,
                https: Boolean(pageData.https)
            });

            if (lastPageSignatures[tabId] === signature) {
                console.log(
                    "Duplicate page analysis ignored for tab:",
                    tabId
                );
                return;
            }

            lastPageSignatures[tabId] = signature;

            analyzeWithBackend(
                actualTabUrl,
                pageData,
                tabId
            );

            return;
        }


        // ==================================================
        // POPUP REQUEST
        // ==================================================

        if (message.type === "GET_TAB_DATA") {
            const tabId = message.tabId;

            sendResponse({
                page_analysis:
                    tabAnalysis[tabId] || null,

                backend_result:
                    tabResults[tabId] || null
            });

            return true;
        }
    }
);


// ======================================================
// SEND DATA TO FLASK
// ======================================================

function analyzeWithBackend(url, pageData, tabId) {
    const requestData = {
        url: url,
        page_analysis: pageData
    };

    console.log("======================================");
    console.log("SENDING TO WEBSHIELD BACKEND:");
    console.log(requestData);

    fetch(
        "http://127.0.0.1:5000/analyze",
        {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(requestData)
        }
    )
        .then(response => {
            console.log(
                "BACKEND HTTP STATUS:",
                response.status
            );

            if (!response.ok) {
                throw new Error(
                    "Backend returned status " +
                    response.status
                );
            }

            return response.json();
        })
        .then(data => {
            console.log("======================================");
            console.log("WEBSHIELD BACKEND RESULT:");
            console.log(data);

            console.log(
                "RISK SCORE:",
                data.risk_score
            );

            console.log(
                "RISK LEVEL:",
                data.risk_level || data.status
            );

            console.log(
                "RISK BREAKDOWN:",
                data.risk_breakdown
            );

            if (data.risk_breakdown) {
                console.log(
                    "ML RISK:",
                    data.risk_breakdown.ml_score
                );

                console.log(
                    "URL RISK:",
                    data.risk_breakdown.url_risk
                );

                console.log(
                    "DOMAIN RISK:",
                    data.risk_breakdown.domain_risk
                );

                console.log(
                    "PAGE RISK:",
                    data.risk_breakdown.page_risk
                );
            }

            console.log(
                "URL REASONS:",
                data.url_reasons
            );

            console.log(
                "DOMAIN REASONS:",
                data.domain_reasons
            );

            console.log(
                "PAGE REASONS:",
                data.page_reasons
            );

            tabResults[tabId] = data;

            console.log(
                "STORED BACKEND RESULT FOR TAB:",
                tabId
            );

            const riskScore = Number(
                data.risk_score || 0
            );

            const riskLevel =
                data.risk_level ||
                data.status ||
                "SAFE";

            // Match the Flask thresholds:
            // SAFE < 30, SUSPICIOUS < 70, HIGH RISK >= 70.
            if (
                riskLevel === "HIGH RISK" &&
                lastNotificationLevels[tabId] !== "HIGH RISK"
            ) {
                createNotification(
                    tabId,
                    "HIGH RISK",
                    "WebShield HIGH RISK",
                    "Phishing risk detected. Risk Score: " +
                        riskScore +
                        "%"
                );

                lastNotificationLevels[tabId] = "HIGH RISK";
            }
            else if (
                riskLevel === "SUSPICIOUS" &&
                lastNotificationLevels[tabId] !== "SUSPICIOUS"
            ) {
                createNotification(
                    tabId,
                    "SUSPICIOUS",
                    "WebShield Warning",
                    "Suspicious website detected. Risk Score: " +
                        riskScore +
                        "%"
                );

                lastNotificationLevels[tabId] = "SUSPICIOUS";
            }
            else if (riskLevel === "SAFE") {
                console.log("WEBSITE SAFE");
                lastNotificationLevels[tabId] = "SAFE";
            }
        })
        .catch(error => {
            console.error(
                "WEBSHIELD FETCH ERROR:",
                error
            );
            tabResults[tabId] = {
                error: "WebShield backend is unavailable. Start app.py and try again.",
                backend_unavailable: true,
                url: url,
            };
        });
}


// ======================================================
// NOTIFICATIONS
// ======================================================

function createNotification(
    tabId,
    level,
    title,
    message
) {
    console.log(
        "Creating",
        level,
        "notification for tab:",
        tabId
    );

    chrome.notifications.create(
        "webshield-" +
            level.toLowerCase().replace(" ", "-") +
            "-" +
            tabId,
        {
            type: "basic",
            iconUrl: "icon.png",
            title: title,
            message: message,
            priority: level === "HIGH RISK" ? 2 : 1
        },
        notificationId => {
            if (chrome.runtime.lastError) {
                console.error(
                    "NOTIFICATION ERROR:",
                    chrome.runtime.lastError.message
                );
            }
            else {
                console.log(
                    "NOTIFICATION CREATED:",
                    notificationId
                );
            }
        }
    );
}


// ======================================================
// TAB CLOSED
// ======================================================

chrome.tabs.onRemoved.addListener(tabId => {
    delete tabAnalysis[tabId];
    delete tabResults[tabId];
    delete lastPageSignatures[tabId];
    delete lastNotificationLevels[tabId];

    console.log(
        "Cleared WebShield data for tab:",
        tabId
    );
});
