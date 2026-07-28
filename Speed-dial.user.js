// ==UserScript==
// @name         חיוג מהיר ומערכת צינתוקים - ימות המשיח (PRO Security)
// @namespace    http://tampermonkey.net/
// @version      2.2
// @description  איתור מספרי טלפון, ממשק הגדרות ויזואלי ומסודר עם הצפנת תצוגת הטוקן
// @match        *://*/*
// @exclude      *://docs.google.com/*
// @exclude      *://github.com/*
// @grant        GM_setValue
// @grant        GM_getValue
// @grant        GM_registerMenuCommand
// @grant        GM_xmlhttpRequest
// @connect      call2all.co.il
// @updateURL    https://github.com/Extension-404/Speed-dial/raw/refs/heads/main/Speed-dial.user.js
// @downloadURL  https://github.com/Extension-404/Speed-dial/raw/refs/heads/main/Speed-dial.user.js
// @run-at       document-idle
// ==/UserScript==
 
(function() {
    'use strict';
 
    // ==========================================
    // 1. הגדרות וניהול גרסאות
    // ==========================================
    const CURRENT_VERSION = "2.2"; // גרסת אבטחה ותצוגה נסתרת לטוקן
    const CONFIG_KEYS = {
        TOKEN: 'ym_token',
        PATH: 'ym_path',
        CALLER_ID: 'ym_caller_id',
        LIST_NAME: 'ym_list_name',
        VERSION: 'ym_script_version'
    };
 
    function getSettings() {
        return {
            token: GM_getValue(CONFIG_KEYS.TOKEN, ''),
            path: GM_getValue(CONFIG_KEYS.PATH, 'ivr2:/'),
            callerId: GM_getValue(CONFIG_KEYS.CALLER_ID, ''),
            listName: GM_getValue(CONFIG_KEYS.LIST_NAME, '')
        };
    }
 
    // ==========================================
    // 2. ממשק משתמש (UI) - חלון הגדרות מעוצב ומאובטח
    // ==========================================
    function openSettingsModal() {
        const existingModal = document.getElementById('ym-settings-modal');
        if (existingModal) existingModal.remove();
 
        const current = getSettings();
 
        const modalHtml = `
            <div id="ym-settings-modal" style="position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.6); z-index: 999999; display: flex; align-items: center; justify-content: center; font-family: Arial, sans-serif; direction: rtl;">
                <div style="background: #fff; padding: 25px; border-radius: 10px; width: 400px; max-width: 90%; box-shadow: 0 4px 20px rgba(0,0,0,0.3); text-align: right; position: relative;">
                    <h3 style="margin-top: 0; color: #333; border-bottom: 2px solid #0066cc; padding-bottom: 10px;">⚙️ הגדרות חיוג מהיר (ימות המשיח)</h3>
                    
                    <label style="display: block; margin-top: 15px; font-weight: bold; font-size: 13px; color: #555;">טוקן המערכת (חובה - מוצג מוסתר):</label>
                    <div style="position: relative; width: 100%; margin-top: 5px;">
                        <input type="password" id="ym-input-token" value="${current.token}" placeholder="077xxxxxxx:123456" style="width: 100%; padding: 8px; padding-left: 35px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; direction: ltr; text-align: left; font-family: monospace;">
                        <span id="ym-toggle-token" style="position: absolute; left: 10px; top: 50%; transform: translateY(-50%); cursor: pointer; user-select: none; font-size: 16px;" title="הצג/הסתר טוקן">👁️</span>
                    </div>
 
                    <label style="display: block; margin-top: 15px; font-weight: bold; font-size: 13px; color: #555;">נתיב שלוחה לעדכון:</label>
                    <input type="text" id="ym-input-path" value="${current.path}" placeholder="ivr2:/ או /" style="width: 100%; padding: 8px; margin-top: 5px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; direction: ltr; text-align: left;">
 
                    <label style="display: block; margin-top: 15px; font-weight: bold; font-size: 13px; color: #555;">מספר זיהוי יוצא (Caller ID):</label>
                    <input type="text" id="ym-input-callerid" value="${current.callerId}" placeholder="השאיר ריק לברירת מחדל של המערכת" style="width: 100%; padding: 8px; margin-top: 5px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box;">
 
                    <label style="display: block; margin-top: 15px; font-weight: bold; font-size: 13px; color: #555;">שם רשימת הצינתוקים (חובה):</label>
                    <input type="text" id="ym-input-listname" value="${current.listName}" placeholder="לדוגמה: test או vip" style="width: 100%; padding: 8px; margin-top: 5px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box;">
 
                    <div style="margin-top: 25px; display: flex; justify-content: space-between;">
                        <button id="ym-btn-save" style="background: #28a745; color: #fff; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; font-weight: bold; flex-grow: 1; margin-left: 10px;">💾 שמור הגדרות</button>
                        <button id="ym-btn-close" style="background: #dc3545; color: #fff; border: none; padding: 10px 15px; border-radius: 5px; cursor: pointer; font-weight: bold;">ביטול</button>
                    </div>
                    <div id="ym-save-status" style="margin-top: 10px; text-align: center; font-weight: bold; font-size: 14px; min-height: 20px;"></div>
                </div>
            </div>
        `;
 
        document.body.insertAdjacentHTML('beforeend', modalHtml);
 
        // מאזין לכפתור העין להצגה/הסתרה של הטוקן
        document.getElementById('ym-toggle-token').addEventListener('click', function() {
            const tokenInput = document.getElementById('ym-input-token');
            if (tokenInput.type === 'password') {
                tokenInput.type = 'text';
                this.innerText = '🔒';
                this.title = 'הסתר טוקן';
            } else {
                tokenInput.type = 'password';
                this.innerText = '👁️';
                this.title = 'הצג טוקן';
            }
        });
 
        document.getElementById('ym-btn-close').addEventListener('click', () => {
            const modal = document.getElementById('ym-settings-modal');
            if (modal) modal.remove();
        });
 
        document.getElementById('ym-btn-save').addEventListener('click', () => {
            const token = document.getElementById('ym-input-token').value.trim();
            const path = document.getElementById('ym-input-path').value.trim();
            const callerId = document.getElementById('ym-input-callerid').value.trim();
            const listName = document.getElementById('ym-input-listname').value.trim();
 
            if (!token || !listName || !path) {
                const statusEl = document.getElementById('ym-save-status');
                statusEl.style.color = 'red';
                statusEl.innerText = '❌ יש למלא טוקן, נתיב ושם רשימה!';
                return;
            }
 
            GM_setValue(CONFIG_KEYS.TOKEN, token);
            GM_setValue(CONFIG_KEYS.PATH, path);
            GM_setValue(CONFIG_KEYS.CALLER_ID, callerId);
            GM_setValue(CONFIG_KEYS.LIST_NAME, listName);
            GM_setValue(CONFIG_KEYS.VERSION, CURRENT_VERSION);
 
            const statusEl = document.getElementById('ym-save-status');
            statusEl.style.color = 'green';
            statusEl.innerText = '✅ ההגדרות נשמרו בהצלחה!';
 
            setTimeout(() => {
                const modal = document.getElementById('ym-settings-modal');
                if (modal) modal.remove();
            }, 1200);
        });
    }
 
    GM_registerMenuCommand("⚙️ הגדרות חיוג מהיר (ימות המשיח)", openSettingsModal);
 
    // ==========================================
    // 3. בדיקה בהפעלה (קפיצה אוטומטית בעת עדכון גרסה)
    // ==========================================
    const storedVersion = GM_getValue(CONFIG_KEYS.VERSION, "");
    const currentConfig = getSettings();
 
    if (!currentConfig.token || !currentConfig.listName || storedVersion !== CURRENT_VERSION) {
        setTimeout(() => {
            openSettingsModal();
            GM_setValue(CONFIG_KEYS.VERSION, CURRENT_VERSION);
        }, 600);
    }
 
    // ==========================================
    // 4. ביצוע קריאות ה-API מול ימות המשיח
    // ==========================================
    function triggerDial(phoneNumber, targetElement) {
        const config = getSettings();
        
        if (!config.token || !config.path || !config.listName) {
            alert("חסרים נתונים. אנא הגדר את פרטי המערכת בחלון שיפתח כעת.");
            openSettingsModal();
            return;
        }
 
        const cleanPhone = phoneNumber.replace(/\D/g, '');
        const originalText = targetElement.innerText;
        targetElement.innerText = "⏳ מחייג...";
        targetElement.style.pointerEvents = "none";
 
        const updateUrl = `https://www.call2all.co.il/ym/api/UpdateExtension?token=${encodeURIComponent(config.token)}&path=${encodeURIComponent(config.path)}&nitoviya_dial_to=${encodeURIComponent(cleanPhone)}`;
 
        GM_xmlhttpRequest({
            method: "GET",
            url: updateUrl,
            onload: function(response) {
                if (response.status === 200) {
                    const callerIdParam = config.callerId ? `&callerId=${encodeURIComponent(config.callerId)}` : '&callerId=';
                    const tzintukUrl = `https://www.call2all.co.il/ym/api/RunTzintuk?token=${encodeURIComponent(config.token)}${callerIdParam}&TzintukTimeOut=9&sayInfoOnAnswer=true&phones=tzl:${encodeURIComponent(config.listName)}`;
 
                    GM_xmlhttpRequest({
                        method: "GET",
                        url: tzintukUrl,
                        onload: function(tzResponse) {
                            if (tzResponse.status === 200) {
                                targetElement.innerText = "✅ נשלח!";
                                targetElement.style.color = "green";
                            } else {
                                targetElement.innerText = "❌ שגיאה בצינתוק";
                                console.error("RunTzintuk Error:", tzResponse.responseText);
                            }
                            resetElement(targetElement, originalText);
                        },
                        onerror: () => {
                            targetElement.innerText = "❌ שגיאת רשת";
                            resetElement(targetElement, originalText);
                        }
                    });
                } else {
                    targetElement.innerText = "❌ כשל בעדכון";
                    console.error("UpdateExtension Error:", response.responseText);
                    resetElement(targetElement, originalText);
                }
            },
            onerror: () => {
                targetElement.innerText = "❌ שגיאת רשת";
                resetElement(targetElement, originalText);
            }
        });
    }
 
    function resetElement(element, text) {
        setTimeout(() => {
            element.innerText = text;
            element.style.pointerEvents = "auto";
            element.style.color = "";
        }, 3000);
    }
 
    // ==========================================
    // 5. סריקה יעילה של ה-DOM ואיתור מספרים
    // ==========================================
    const PHONE_REGEX = /(?:(?:(\+?972|\b0)(?:[-.\s]?\d){8,9})|\b(1[78]00|1599)(?:[-.\s]?\d){6}\b|\*\d{3,4}\b)/g;
    const IGNORE_TAGS = new Set(['SCRIPT', 'STYLE', 'NOSCRIPT', 'TEXTAREA', 'INPUT', 'SELECT', 'A', 'BUTTON']);
 
    function scanAndReplace(rootNode) {
        const walker = document.createTreeWalker(
            rootNode,
            NodeFilter.SHOW_TEXT,
            {
                acceptNode: function(node) {
                    if (!node.parentNode || IGNORE_TAGS.has(node.parentNode.nodeName)) {
                        return NodeFilter.FILTER_REJECT;
                    }
                    if (node.parentNode.hasAttribute('data-ym-dialer')) {
                        return NodeFilter.FILTER_REJECT;
                    }
                    return PHONE_REGEX.test(node.nodeValue) ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_SKIP;
                }
            }
        );
 
        const nodesToProcess = [];
        let currentNode;
        while (currentNode = walker.nextNode()) {
            nodesToProcess.push(currentNode);
        }
 
        nodesToProcess.forEach(node => {
            const text = node.nodeValue;
            const fragment = document.createDocumentFragment();
            let lastIndex = 0;
            let match;
 
            PHONE_REGEX.lastIndex = 0;
 
            while ((match = PHONE_REGEX.exec(text)) !== null) {
                if (match.index > lastIndex) {
                    fragment.appendChild(document.createTextNode(text.slice(lastIndex, match.index)));
                }
 
                const phoneNumber = match[0];
                const dialBadge = document.createElement('span');
                dialBadge.innerText = phoneNumber;
                dialBadge.title = "לחץ לחיוג מהיר באמצעות ימות המשיח";
                dialBadge.setAttribute('data-ym-dialer', 'true');
                dialBadge.style.cssText = "color: #0066cc; text-decoration: underline; cursor: pointer; font-weight: bold; background-color: #e6f2ff; padding: 0 3px; border-radius: 3px; margin: 0 1px;";
                
                dialBadge.addEventListener('click', (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    triggerDial(phoneNumber, dialBadge);
                });
 
                fragment.appendChild(dialBadge);
                lastIndex = PHONE_REGEX.lastIndex;
            }
 
            if (lastIndex < text.length) {
                fragment.appendChild(document.createTextNode(text.slice(lastIndex)));
            }
 
            if (node.parentNode) {
                node.parentNode.replaceChild(fragment, node);
            }
        });
    }
 
    // ==========================================
    // 6. הפעלה ומעקב אחרי תוכן דינמי (Debounce)
    // ==========================================
    scanAndReplace(document.body);
 
    let debounceTimer = null;
    const observer = new MutationObserver((mutations) => {
        if (debounceTimer) clearTimeout(debounceTimer);
        
        debounceTimer = setTimeout(() => {
            mutations.forEach(mutation => {
                mutation.addedNodes.forEach(node => {
                    if (node.nodeType === Node.ELEMENT_NODE && !IGNORE_TAGS.has(node.nodeName)) {
                        if (node.id === 'ym-settings-modal') return;
                        scanAndReplace(node);
                    } else if (node.nodeType === Node.TEXT_NODE && node.parentNode && !IGNORE_TAGS.has(node.parentNode.nodeName)) {
                        if (PHONE_REGEX.test(node.nodeValue)) {
                            scanAndReplace(node.parentNode);
                        }
                    }
                });
            });
        }, 400);
    });
 
    observer.observe(document.body, {
        childList: true,
        subtree: true
    });
 
})();
