console.log("WebShield popup loaded");


// ============================================================
// GET CURRENT TAB
// ============================================================

chrome.tabs.query(
    {
        active: true,
        currentWindow: true
    },

    tabs => {

        if (!tabs || !tabs[0]) {

            showError(
                "Unable to detect current tab."
            );

            return;
        }


        const tab = tabs[0];

        const url = tab.url;

        const tabId = tab.id;


        console.log(
            "Popup current tab:",
            tab
        );


        document.getElementById(
            "url"
        ).textContent =
            url || "Unknown";


        // ----------------------------------------------------
        // INTERNAL PAGE
        // ----------------------------------------------------

        if (
            !url ||
            url.startsWith("chrome://") ||
            url.startsWith("chrome-extension://") ||
            url.startsWith("edge://") ||
            url.startsWith("about:")
        ) {

            showError(
                "Cannot analyze this Chrome page."
            );

            return;
        }


        requestTabData(
            tabId,
            0
        );

    }
);


// ============================================================
// REQUEST DATA
// ============================================================

function requestTabData(
    tabId,
    attempt
) {

    console.log(
        "Requesting WebShield data:",
        tabId,
        "attempt:",
        attempt
    );


    chrome.runtime.sendMessage(

        {
            type: "GET_TAB_DATA",

            tabId: tabId
        },

        response => {

            if (chrome.runtime.lastError) {

                console.error(
                    "Popup communication error:",
                    chrome.runtime.lastError.message
                );

                showError(
                    "Extension communication error."
                );

                return;
            }


            console.log(
                "Popup received:",
                response
            );


            if (!response) {

                showError(
                    "No analysis available yet."
                );

                return;
            }


            const pageAnalysis =
                response.page_analysis;


            const backendResult =
                response.backend_result;


            // ------------------------------------------------
            // PAGE ANALYSIS
            // ------------------------------------------------

            if (pageAnalysis) {

                displayPageAnalysis(
                    pageAnalysis
                );

            }


            // ------------------------------------------------
            // BACKEND RESULT
            // ------------------------------------------------

            if (backendResult) {

                displayResult(
                    backendResult
                );

                return;
            }


            // ------------------------------------------------
            // Backend hasn't finished yet.
            // Try a few times.
            // ------------------------------------------------

            if (attempt < 5) {

                console.log(
                    "Backend result not ready. Retrying..."
                );


                setTimeout(
                    () => {

                        requestTabData(
                            tabId,
                            attempt + 1
                        );

                    },
                    500
                );

            }

            else {

                document.getElementById(
                    "risk"
                ).textContent =
                    "Analyzing...";

                document.getElementById(
                    "score"
                ).textContent =
                    "Risk Score: --";

            }

        }
    );

}


// ============================================================
// DISPLAY BACKEND RESULT
// ============================================================

function displayResult(data) {

    if (data && data.error) {
        showError(data.error);
        return;
    }

    const riskElement =
        document.getElementById("risk");


    const scoreElement =
        document.getElementById("score");


    const reasonsElement =
        document.getElementById("reasons");


    const contextElement =
        document.getElementById("context");


    // --------------------------------------------------------
    // Risk level
    // --------------------------------------------------------

    riskElement.textContent =
        data.risk_level;


    scoreElement.textContent =
        "Risk Score: " +
        data.risk_score +
        "%";


    contextElement.textContent =
        data.context;


    // --------------------------------------------------------
    // Colour
    // --------------------------------------------------------

    riskElement.className =
        "risk";


    if (data.risk_score < 30) {

        riskElement.classList.add(
            "safe"
        );

    }

    else if (data.risk_score < 70) {

        riskElement.classList.add(
            "suspicious"
        );

    }

    else {

        riskElement.classList.add(
            "danger"
        );

    }


    // --------------------------------------------------------
    // Risk breakdown
    // --------------------------------------------------------

    if (data.risk_breakdown) {

        const breakdown =
            data.risk_breakdown;


        setText(
            "ml-score",
            breakdown.ml_score
        );

        setText(
            "dl-score",
            breakdown.dl_score
        );

        setBar(
            "dl-bar",
            breakdown.dl_score
        );

        setText(
            "url-score",
            breakdown.url_risk
        );


        setText(
            "domain-score",
            breakdown.domain_risk
        );


        setText(
            "page-score",
            breakdown.page_risk == null ? "Not analyzed" : breakdown.page_risk
        );


        setBar(
            "ml-bar",
            breakdown.ml_score
        );


        setBar(
            "url-bar",
            breakdown.url_risk
        );


        setBar(
            "domain-bar",
            breakdown.domain_risk
        );


        setBar(
            "page-bar",
            breakdown.page_risk == null ? 0 : breakdown.page_risk
        );

    }


    // --------------------------------------------------------
    // Detection reasons
    // --------------------------------------------------------

    reasonsElement.innerHTML = "";


    if (
        data.reasons &&
        data.reasons.length > 0
    ) {

        data.reasons.forEach(reason => {

            const li =
                document.createElement("li");


            li.textContent =
                reason;


            reasonsElement.appendChild(
                li
            );

        });

    }

    else {

        const li =
            document.createElement("li");


        li.textContent =
            "No suspicious indicators found.";


        reasonsElement.appendChild(
            li
        );

    }

}


// ============================================================
// DISPLAY PAGE ANALYSIS
// ============================================================

function displayPageAnalysis(pageData) {

    console.log(
        "Displaying page analysis:",
        pageData
    );


    const details =
        document.getElementById(
            "page-details"
        );


    if (!pageData) {

        details.textContent =
            "No page analysis available.";

        return;
    }


    details.innerHTML = "";


    const fields = [

        [
            "Forms",
            pageData.forms ?? 0
        ],

        [
            "Password Fields",
            pageData.password_fields ?? 0
        ],

        [
            "Iframes",
            pageData.iframes ?? 0
        ],

        [
            "External Links",
            pageData.external_links ?? 0
        ],

        [
            "External Form Actions",
            pageData.external_form_actions ?? 0
        ],

        [
            "HTTPS",
            pageData.https
                ? "Yes"
                : "No"
        ]

    ];


    fields.forEach(
        ([label, value]) => {

            const p =
                document.createElement("p");


            p.className =
                "page-detail";


            p.innerHTML =
                "<strong>" +
                label +
                ":</strong> " +
                value;


            details.appendChild(
                p
            );

        }
    );

}


// ============================================================
// SET BREAKDOWN TEXT
// ============================================================

function setText(
    id,
    value
) {

    const element =
        document.getElementById(id);


    if (element) {

        element.textContent =
            value == null ? "Not analyzed" : value + "%";

    }

}


// ============================================================
// SET BREAKDOWN BAR
// ============================================================

function setBar(
    id,
    value
) {

    const bar =
        document.getElementById(id);


    if (!bar) {
        return;
    }


    const width =
        Math.min(
            Math.max(
                Number(value) || 0,
                0
            ),
            100
        );


    bar.style.width =
        width + "%";

}


// ============================================================
// ERROR
// ============================================================

function showError(message) {

    document.getElementById(
        "risk"
    ).textContent =
        "ERROR";


    document.getElementById(
        "risk"
    ).className =
        "risk danger";


    document.getElementById(
        "score"
    ).textContent =
        message;

}