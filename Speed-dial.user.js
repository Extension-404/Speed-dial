// ==UserScript==
// @name         חיוג מהיר ומערכת צינתוקים - ימות המשיח (PRO Security)
// @namespace    http://tampermonkey.net/
// @version      2.6.0
// @description  בחירת מכשיר אישי, בחירת זיהוי יוצא אינטראקטיבית, עדכון שלוחות מקביל וחסימות אבטחה
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
    const CURRENT_VERSION = "2.6.0";
    const CONFIG_KEYS = {
        TOKEN: 'ym_token',
        PATH: 'ym_path',
        CALLER_ID: 'ym_caller_id',
        PROMPT_CALLER_ID: 'ym_prompt_caller_id',
        ALL_APPROVED_IDS: 'ym_all_approved_ids',
        ACTIVE_CALLER_IDS: 'ym_active_ids',
        LIST_NAME: 'ym_list_name',
        // חדש: הגדרות המכשיר האישי
        USER_PATH: 'ym_user_path',
        MY_PHONES: 'ym_my_phones',
        DEFAULT_MY_PHONE: 'ym_default_my_phone',
        PROMPT_MY_PHONE: 'ym_prompt_my_phone',
        VERSION: 'ym_script_version'
    };

    function getSettings() {
        return {
            token: GM_getValue(CONFIG_KEYS.TOKEN, ''),
            path: GM_getValue(CONFIG_KEYS.PATH, 'ivr2:/'),
            callerId: GM_getValue(CONFIG_KEYS.CALLER_ID, ''),
            promptCallerId: GM_getValue(CONFIG_KEYS.PROMPT_CALLER_ID, false),
            allApprovedIds: JSON.parse(GM_getValue(CONFIG_KEYS.ALL_APPROVED_IDS, '[]')),
            activeCallerIds: JSON.parse(GM_getValue(CONFIG_KEYS.ACTIVE_CALLER_IDS, '[]')),
            listName: GM_getValue(CONFIG_KEYS.LIST_NAME, ''),
            
            userPath: GM_getValue(CONFIG_KEYS.USER_PATH, ''),
            myPhones: JSON.parse(GM_getValue(CONFIG_KEYS.MY_PHONES, '[]')),
            defaultMyPhone: GM_getValue(CONFIG_KEYS.DEFAULT_MY_PHONE, ''),
            promptMyPhone: GM_getValue(CONFIG_KEYS.PROMPT_MY_PHONE, false)
        };
    }

    // מעטפת להבטחת עבודה מהירה ומסודרת מול ימות המשיח (Promise wrapper)
    function ymFetch(url) {
        return new Promise((resolve, reject) => {
            GM_xmlhttpRequest({
                method: "GET",
                url: url,
                onload: function(response) {
                    if (response.status === 200) {
                        resolve(response.responseText);
                    } else {
                        reject("HTTP Error " + response.status);
                    }
                },
                onerror: function() {
                    reject("Network Error");
                }
            });
        });
    }

    // משיכת מספרי זיהוי יוצא מהשרת
    function fetchApprovedCallerIdsFromApi(token, callback) {
        if (!token) return callback(false, "יש להזין טוקן תחילה!");
        const url = `https://www.call2all.co.il/ym/api/GetApprovedCallerIDs?token=${encodeURIComponent(token)}`;
        
        ymFetch(url).then(res => {
            const data = JSON.parse(res);
            let ids = [];
            if (data.call) {
                ids = [...(data.call.callerIds || []), ...(data.call.secondaryDids || [])];
            } else if (Array.isArray(data.callerIds)) {
                ids = data.callerIds;
            }
            ids = [...new Set(ids)].map(id => id.replace(/^(\+)?972/, '0'));
            
            if (ids.length > 0) {
                GM_setValue(CONFIG_KEYS.ALL_APPROVED_IDS, JSON.stringify(ids));
                callback(true, ids);
            } else {
                callback(false, "לא נמצאו מספרים מאושרים בחשבון זה.");
            }
        }).catch(err => callback(false, "שגיאת תקשורת מול שרתי ימות המשיח."));
    }

    // ==========================================
    // 3. ממשק משתמש (UI) - חלון הגדרות מעוצב ומחולק
    // ==========================================
    function openSettingsModal() {
        const existingModal = document.getElementById('ym-settings-modal');
        if (existingModal) existingModal.remove();

        const current = getSettings();
        
        let callerIdOptions = `<option value="">-- ברירת מחדל של המערכת --</option>`;
        current.allApprovedIds.forEach(id => {
            const selected = (id === current.callerId) ? 'selected' : '';
            callerIdOptions += `<option value="${id}" ${selected}>${id}</option>`;
        });
        if (current.callerId && !current.allApprovedIds.includes(current.callerId)) {
            callerIdOptions += `<option value="${current.callerId}" selected>${current.callerId} (ידני)</option>`;
        }

        const modalHtml = `
            <div id="ym-settings-modal" style="position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.6); z-index: 999999; display: flex; align-items: center; justify-content: center; font-family: Arial, sans-serif; direction: rtl;">
                <div style="background: #fff; padding: 25px; border-radius: 12px; width: 480px; max-width: 95%; max-height: 90vh; overflow-y: auto; box-shadow: 0 5px 25px rgba(0,0,0,0.3); text-align: right; position: relative;">
                    <h3 style="margin-top: 0; color: #333; border-bottom: 2px solid #0066cc; padding-bottom: 10px;">⚙️ הגדרות מערכת צינתוקים (PRO)</h3>
                    
                    <label style="display: block; margin-top: 15px; font-weight: bold; font-size: 13px; color: #555;">טוקן המערכת (מוסתר):</label>
                    <div style="position: relative; width: 100%; margin-top: 5px;">
                        <input type="password" id="ym-input-token" value="${current.token}" placeholder="077xxxxxxx:123456" style="width: 100%; padding: 8px; padding-left: 35px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; direction: ltr; text-align: left; font-family: monospace;">
                        <span id="ym-toggle-token" style="position: absolute; left: 10px; top: 50%; transform: translateY(-50%); cursor: pointer; font-size: 16px;" title="הצג/הסתר">👁️</span>
                    </div>

                    <label style="display: block; margin-top: 15px; font-weight: bold; font-size: 13px; color: #555;">שם רשימת הצינתוקים - טריגר (חובה):</label>
                    <input type="text" id="ym-input-listname" value="${current.listName}" placeholder="לדוגמה: vip או test" style="width: 100%; padding: 8px; margin-top: 5px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box;">

                    <!-- שלב 1: יעד החיוג -->
                    <div style="background: #f8f9fa; padding: 12px; border-radius: 8px; border: 1px solid #e9ecef; margin-top: 15px;">
                        <h4 style="margin: 0 0 10px 0; color: #0056b3; font-size: 14px;">📞 שלב 1: יעדי החיוג (למי מתקשרים)</h4>
                        
                        <label style="display: block; font-weight: bold; font-size: 12px; color: #555;">נתיב שלוחת היעד לעדכון (ניתוביה):</label>
                        <input type="text" id="ym-input-path" value="${current.path}" placeholder="ivr2:/ או /" style="width: 100%; padding: 8px; margin-top: 5px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; direction: ltr; text-align: left;">

                        <label style="display: block; margin-top: 10px; font-weight: bold; font-size: 12px; color: #555;">זיהוי יוצא קבוע (Caller ID):</label>
                        <div style="display: flex; gap: 5px; margin-top: 5px;">
                            <select id="ym-select-callerid" style="flex-grow: 1; padding: 8px; border: 1px solid #ccc; border-radius: 4px; background: #fff; font-size: 14px;">
                                ${callerIdOptions}
                            </select>
                            <button id="ym-btn-fetch-ids" style="background: #17a2b8; color: #fff; border: none; padding: 0 12px; border-radius: 4px; cursor: pointer; font-weight: bold; font-size: 12px; white-space: nowrap;">🔄 מול ימות</button>
                        </div>

                        <label style="display: flex; align-items: center; cursor: pointer; font-weight: bold; font-size: 12px; color: #0056b3; margin-top: 10px;">
                            <input type="checkbox" id="ym-check-prompt" ${current.promptCallerId ? 'checked' : ''} style="margin-left: 8px; width: 16px; height: 16px;">
                            🔔 שאל אותי באיזה זיהוי יוצא להשתמש לפני כל חיוג
                        </label>
                        
                        <div id="ym-pool-container" style="display: ${current.promptCallerId ? 'block' : 'none'}; margin-top: 10px; padding-top: 8px; border-top: 1px dashed #ccc;">
                            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                                <span style="font-size: 11px; color: #555; font-weight: bold;">📋 בחר אילו מספרים יופיעו בחלון לבחירה מהירה:</span>
                                <div style="display: flex; gap: 4px;">
                                    <button type="button" id="ym-btn-select-all" style="background: #e2e3e5; border: 1px solid #ccc; padding: 2px 6px; border-radius: 4px; font-size: 11px; cursor: pointer; font-weight: bold;">☑️ בחר הכל</button>
                                    <button type="button" id="ym-btn-clear-all" style="background: #e2e3e5; border: 1px solid #ccc; padding: 2px 6px; border-radius: 4px; font-size: 11px; cursor: pointer; font-weight: bold;">⬜ נקה</button>
                                </div>
                            </div>
                            <div id="ym-checkbox-list" style="max-height: 100px; overflow-y: auto; background: #fff; border: 1px solid #ddd; padding: 6px; border-radius: 6px; display: grid; grid-template-columns: 1fr 1fr; gap: 6px;"></div>
                        </div>
                    </div>

                    <!-- שלב 2: המכשיר האישי -->
                    <div style="background: #e6f2ff; padding: 12px; border-radius: 8px; border: 1px solid #b8daff; margin-top: 15px;">
                        <h4 style="margin: 0 0 10px 0; color: #004085; font-size: 14px;">📱 שלב 2: המכשיר שלך (לאן המערכת תחייג אליך)</h4>
                        
                        <label style="display: block; font-weight: bold; font-size: 12px; color: #555;">נתיב שלוחה לעדכון הטלפון שלך (אופציונלי):</label>
                        <input type="text" id="ym-input-user-path" value="${current.userPath}" placeholder="לדוגמה: ivr2:/my_phone" style="width: 100%; padding: 8px; margin-top: 5px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; direction: ltr; text-align: left;">
                        
                        <label style="display: block; margin-top: 10px; font-weight: bold; font-size: 12px; color: #555;">רשימת המכשירים שלך (מופרדים בפסיק):</label>
                        <input type="text" id="ym-input-my-phones" value="${current.myPhones.join(', ')}" placeholder="0501234567, 0771234567" style="width: 100%; padding: 8px; margin-top: 5px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box;">
                        
                        <label style="display: block; margin-top: 10px; font-weight: bold; font-size: 12px; color: #555;">מכשיר ברירת מחדל אליך:</label>
                        <select id="ym-select-default-my-phone" style="width: 100%; padding: 8px; margin-top: 5px; border: 1px solid #ccc; border-radius: 4px; background: #fff; font-size: 14px;"></select>
                        
                        <label style="display: flex; align-items: center; cursor: pointer; font-weight: bold; font-size: 12px; color: #004085; margin-top: 10px;">
                            <input type="checkbox" id="ym-check-prompt-my-phone" ${current.promptMyPhone ? 'checked' : ''} style="margin-left: 8px; width: 16px; height: 16px;">
                            🔔 שאל אותי לאיזה מכשיר לחייג אליי לפני כל שיחה
                        </label>
                    </div>

                    <div style="margin-top: 25px; display: flex; justify-content: space-between;">
                        <button id="ym-btn-save" style="background: #28a745; color: #fff; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; font-weight: bold; flex-grow: 1; margin-left: 10px;">💾 שמור הגדרות</button>
                        <button id="ym-btn-close" style="background: #dc3545; color: #fff; border: none; padding: 10px 15px; border-radius: 5px; cursor: pointer; font-weight: bold;">ביטול</button>
                    </div>
                    <div id="ym-save-status" style="margin-top: 10px; text-align: center; font-weight: bold; font-size: 14px; min-height: 20px;"></div>
                </div>
            </div>
        `;

        document.body.insertAdjacentHTML('beforeend', modalHtml);

        // רינדור רשימות המספרים
        function renderCheckboxList(allIds, activeIds) {
            const container = document.getElementById('ym-checkbox-list');
            if (allIds.length === 0) {
                container.style.gridTemplateColumns = "1fr";
                container.innerHTML = `<div style="color: #dc3545; font-size: 12px;">לא נמצאו מספרים במאגר. לחץ על "🔄 מול ימות".</div>`;
                return;
            }
            container.style.gridTemplateColumns = "1fr 1fr";
            container.innerHTML = allIds.map(id => {
                const isChecked = activeIds.includes(id) ? 'checked' : '';
                return `
                    <label style="display: flex; align-items: center; font-size: 12px; color: #333; background: #f1f3f5; padding: 4px 6px; border-radius: 4px; cursor: pointer; user-select: none;">
                        <input type="checkbox" class="ym-pool-item" value="${id}" ${isChecked} style="margin-left: 6px; cursor: pointer;">
                        <span style="direction: ltr;">${id}</span>
                    </label>
                `;
            }).join('');
        }

        function populateMyPhonesSelect() {
            const inputVal = document.getElementById('ym-input-my-phones').value;
            const phones = inputVal.split(',').map(p => p.trim()).filter(p => p);
            const select = document.getElementById('ym-select-default-my-phone');
            const currentVal = select.value || current.defaultMyPhone;
            
            select.innerHTML = '<option value="">-- בחר מכשיר אישי --</option>' + 
                phones.map(p => `<option value="${p}" ${p === currentVal ? 'selected' : ''}>${p}</option>`).join('');
        }

        renderCheckboxList(current.allApprovedIds, current.activeCallerIds);
        document.getElementById('ym-input-my-phones').addEventListener('input', populateMyPhonesSelect);
        populateMyPhonesSelect();

        // מאזיני לחיצות
        document.getElementById('ym-btn-select-all').addEventListener('click', () => document.querySelectorAll('.ym-pool-item').forEach(cb => cb.checked = true));
        document.getElementById('ym-btn-clear-all').addEventListener('click', () => document.querySelectorAll('.ym-pool-item').forEach(cb => cb.checked = false));
        
        document.getElementById('ym-check-prompt').addEventListener('change', function() {
            document.getElementById('ym-pool-container').style.display = this.checked ? 'block' : 'none';
        });

        document.getElementById('ym-toggle-token').addEventListener('click', function() {
            const input = document.getElementById('ym-input-token');
            input.type = (input.type === 'password') ? 'text' : 'password';
            this.innerText = (input.type === 'password') ? '👁️' : '🔒';
        });

        document.getElementById('ym-btn-close').addEventListener('click', () => document.getElementById('ym-settings-modal').remove());

        document.getElementById('ym-btn-fetch-ids').addEventListener('click', function() {
            const token = document.getElementById('ym-input-token').value.trim();
            const statusEl = document.getElementById('ym-save-status');
            this.innerText = "⏳"; this.disabled = true;

            fetchApprovedCallerIdsFromApi(token, (success, result) => {
                this.innerText = "🔄 מול ימות"; this.disabled = false;
                if (success) {
                    const selectEl = document.getElementById('ym-select-callerid');
                    const currentVal = selectEl.value;
                    selectEl.innerHTML = `<option value="">-- ברירת מחדל --</option>` + 
                        result.map(id => `<option value="${id}" ${id === currentVal ? 'selected' : ''}>${id}</option>`).join('');
                    renderCheckboxList(result, []);
                    statusEl.style.color = 'green';
                    statusEl.innerText = '✅ המספרים סונכרונו! בחר כעת את המספרים הרצויים ב-V.';
                } else {
                    statusEl.style.color = 'red'; statusEl.innerText = '❌ ' + result;
                }
            });
        });

        document.getElementById('ym-btn-save').addEventListener('click', () => {
            const token = document.getElementById('ym-input-token').value.trim();
            const path = document.getElementById('ym-input-path').value.trim();
            const callerId = document.getElementById('ym-select-callerid').value;
            const promptCallerId = document.getElementById('ym-check-prompt').checked;
            const listName = document.getElementById('ym-input-listname').value.trim();
            
            const userPath = document.getElementById('ym-input-user-path').value.trim();
            const myPhonesArr = document.getElementById('ym-input-my-phones').value.split(',').map(p => p.trim()).filter(p => p);
            const defaultMyPhone = document.getElementById('ym-select-default-my-phone').value;
            const promptMyPhone = document.getElementById('ym-check-prompt-my-phone').checked;

            const selectedActiveIds = [];
            document.querySelectorAll('.ym-pool-item:checked').forEach(cb => selectedActiveIds.push(cb.value));

            if (!token || !listName || !path) {
                document.getElementById('ym-save-status').style.color = 'red';
                document.getElementById('ym-save-status').innerText = '❌ יש למלא טוקן, נתיב מטרה ושם רשימה!';
                return;
            }

            GM_setValue(CONFIG_KEYS.TOKEN, token);
            GM_setValue(CONFIG_KEYS.PATH, path);
            GM_setValue(CONFIG_KEYS.CALLER_ID, callerId);
            GM_setValue(CONFIG_KEYS.PROMPT_CALLER_ID, promptCallerId);
            GM_setValue(CONFIG_KEYS.ACTIVE_CALLER_IDS, JSON.stringify(selectedActiveIds));
            GM_setValue(CONFIG_KEYS.LIST_NAME, listName);
            
            GM_setValue(CONFIG_KEYS.USER_PATH, userPath);
            GM_setValue(CONFIG_KEYS.MY_PHONES, JSON.stringify(myPhonesArr));
            GM_setValue(CONFIG_KEYS.DEFAULT_MY_PHONE, defaultMyPhone);
            GM_setValue(CONFIG_KEYS.PROMPT_MY_PHONE, promptMyPhone);
            
            GM_setValue(CONFIG_KEYS.VERSION, CURRENT_VERSION);

            document.getElementById('ym-save-status').style.color = 'green';
            document.getElementById('ym-save-status').innerText = '✅ ההגדרות נשמרו בהצלחה!';

            setTimeout(() => document.getElementById('ym-settings-modal').remove(), 1200);
        });
    }

    GM_registerMenuCommand("⚙️ הגדרות חיוג מהיר (ימות המשיח)", openSettingsModal);

    // ==========================================
    // 4. חלון בחירה מהיר חכם (Smart Quick Dial Modal)
    // ==========================================
    function openQuickDialModal(phoneNumber, targetElement, onExecute) {
        const config = getSettings();
        const existingModal = document.getElementById('ym-quick-dial-modal');
        if (existingModal) existingModal.remove();

        const promptCallerId = config.promptCallerId;
        const promptMyPhone = config.promptMyPhone && config.myPhones.length > 0;
        const callerIdsToDisplay = (config.activeCallerIds.length > 0) ? config.activeCallerIds : config.allApprovedIds;

        let modalInner = '';

        if (promptCallerId && promptMyPhone) {
            // תפריט בחירה כפול ומקצועי
            let callerIdOpts = `<option value="">🌐 ברירת מחדל של המערכת</option>` + callerIdsToDisplay.map(id => `<option value="${id}">${id}</option>`).join('');
            let myPhoneOpts = config.myPhones.map(id => `<option value="${id}">${id}</option>`).join('');
            
            modalInner = `
                <div style="text-align: right; margin-bottom: 15px;">
                    <label style="font-size: 13px; font-weight: bold; color: #555;">📱 לאיזה מכשיר לחייג אליך?</label>
                    <select id="q-my-phone" style="width:100%; padding:8px; margin-top:3px; border-radius:4px; font-size:14px; border:1px solid #ccc;">${myPhoneOpts}</select>
                </div>
                <div style="text-align: right; margin-bottom: 20px;">
                    <label style="font-size: 13px; font-weight: bold; color: #555;">📞 איזה זיהוי יוצא להציג ליעד?</label>
                    <select id="q-caller-id" style="width:100%; padding:8px; margin-top:3px; border-radius:4px; font-size:14px; border:1px solid #ccc;">${callerIdOpts}</select>
                </div>
                <button id="q-execute-btn" style="background:#28a745; color:#fff; border:none; padding:10px; width:100%; border-radius:5px; font-weight:bold; cursor:pointer; font-size:15px; margin-bottom:10px;">🚀 הוצא שיחה עכשיו!</button>
            `;
        } else if (promptCallerId) {
            // כפתורי לחיצה אחת - רק זיהוי יוצא
            let btns = callerIdsToDisplay.map(id => `<button class="ym-quick-btn" data-type="callerid" data-val="${id}">📞 ${id}</button>`).join('');
            modalInner = `
                <p style="font-size: 13px; color: #666; margin-bottom: 10px;">בחר זיהוי יוצא להוצאת השיחה:</p>
                <div style="display: flex; flex-direction: column; gap: 8px; max-height: 260px; overflow-y: auto; margin-bottom: 15px;">
                    <button class="ym-quick-btn" data-type="callerid" data-val="">🌐 ברירת מחדל של המערכת</button>
                    ${btns}
                </div>
            `;
        } else if (promptMyPhone) {
            // כפתורי לחיצה אחת - רק לבחירת הטלפון שלי
            let btns = config.myPhones.map(id => `<button class="ym-quick-btn" data-type="myphone" data-val="${id}">📱 ${id}</button>`).join('');
            modalInner = `
                <p style="font-size: 13px; color: #666; margin-bottom: 10px;">לאיזה מכשיר שלך לחייג עכשיו?</p>
                <div style="display: flex; flex-direction: column; gap: 8px; max-height: 260px; overflow-y: auto; margin-bottom: 15px;">
                    ${btns}
                </div>
            `;
        }

        const modalHtml = `
            <div id="ym-quick-dial-modal" style="position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 9999999; display: flex; align-items: center; justify-content: center; font-family: Arial, sans-serif; direction: rtl;">
                <div style="background: #fff; padding: 20px; border-radius: 12px; width: 340px; max-width: 90%; box-shadow: 0 5px 25px rgba(0,0,0,0.3); text-align: center; border-top: 4px solid #0066cc;">
                    <h4 style="margin: 0 0 15px 0; color: #333; font-size: 16px;">חיוג מהיר אל: <span style="color: #0066cc; direction: ltr; display: inline-block;">${phoneNumber}</span></h4>
                    ${modalInner}
                    <button id="ym-quick-cancel" style="background: #dc3545; color: #fff; border: none; padding: 8px 20px; border-radius: 5px; cursor: pointer; font-weight: bold; font-size: 13px; width: 100%;">ביטול חיוג</button>
                </div>
            </div>
        `;

        document.body.insertAdjacentHTML('beforeend', modalHtml);

        if (promptCallerId && promptMyPhone) {
            document.getElementById('q-execute-btn').addEventListener('click', () => {
                const sMyPhone = document.getElementById('q-my-phone').value;
                const sCallerId = document.getElementById('q-caller-id').value;
                document.getElementById('ym-quick-dial-modal').remove();
                onExecute(sCallerId, sMyPhone);
            });
        } else {
            document.querySelectorAll('.ym-quick-btn').forEach(btn => {
                btn.style.cssText = "background: #f8f9fa; border: 1px solid #ced4da; padding: 10px; border-radius: 6px; cursor: pointer; font-weight: bold; font-size: 15px; color: #0056b3; transition: all 0.2s;";
                if(btn.getAttribute('data-val') === '') { btn.style.background = '#e2e3e5'; btn.style.color = '#383d41'; }
                
                btn.addEventListener('mouseover', function() { this.style.background = '#e6f2ff'; this.style.borderColor = '#80bdff'; });
                btn.addEventListener('mouseout', function() { this.style.background = (this.getAttribute('data-val') === '') ? '#e2e3e5' : '#f8f9fa'; this.style.borderColor = '#ced4da'; });
                
                btn.addEventListener('click', function() {
                    const type = this.getAttribute('data-type');
                    const val = this.getAttribute('data-val');
                    document.getElementById('ym-quick-dial-modal').remove();
                    
                    if (type === 'callerid') {
                        onExecute(val, config.defaultMyPhone);
                    } else {
                        onExecute(config.callerId, val);
                    }
                });
            });
        }

        document.getElementById('ym-quick-cancel').addEventListener('click', () => {
            document.getElementById('ym-quick-dial-modal').remove();
            resetElement(targetElement, phoneNumber);
        });
    }

    // ==========================================
    // 5. ניהול קריאות מבוסס תורים (Sequential API)
    // ==========================================
    function triggerDial(phoneNumber, targetElement) {
        const config = getSettings();
        
        if (!config.token || !config.path || !config.listName) {
            alert("❌ חסרים פרטי הגדרות. אנא הגדר את המערכת בחלון שיפתח כעת.");
            openSettingsModal(); return;
        }

        const cleanPhone = phoneNumber.replace(/\D/g, '');
        const originalText = targetElement.innerText;
        targetElement.innerText = "⏳ מכין חיוג...";
        targetElement.style.pointerEvents = "none";

        const promptCallerId = config.promptCallerId;
        const promptMyPhone = config.promptMyPhone && config.myPhones.length > 0;

        if (promptCallerId || promptMyPhone) {
            openQuickDialModal(phoneNumber, targetElement, (selectedCallerId, selectedMyPhone) => {
                executeCall(cleanPhone, selectedCallerId, selectedMyPhone, targetElement, originalText);
            });
        } else {
            executeCall(cleanPhone, config.callerId, config.defaultMyPhone, targetElement, originalText);
        }
    }

    async function executeCall(cleanPhone, callerIdToUse, myPhoneToUse, targetElement, originalText) {
        const config = getSettings();
        try {
            // עדכון היעד
            targetElement.innerText = "⏳ מעדכן יעד...";
            const url1 = `https://www.call2all.co.il/ym/api/UpdateExtension?token=${encodeURIComponent(config.token)}&path=${encodeURIComponent(config.path)}&nitoviya_dial_to=${encodeURIComponent(cleanPhone)}`;
            await ymFetch(url1);

            // עדכון המכשיר האישי (רק אם הוזן נתיב מיוחד למכשיר)
            if (config.userPath && myPhoneToUse) {
                targetElement.innerText = "⏳ מעדכן מכשיר...";
                const url2 = `https://www.call2all.co.il/ym/api/UpdateExtension?token=${encodeURIComponent(config.token)}&path=${encodeURIComponent(config.userPath)}&nitoviya_dial_to=${encodeURIComponent(myPhoneToUse)}`;
                await ymFetch(url2);
            }

            // הפעלת הצינתוק
            targetElement.innerText = "⏳ מצנתק...";
            const callerIdParam = callerIdToUse ? `&callerId=${encodeURIComponent(callerIdToUse)}` : '&callerId=';
            const tzintukUrl = `https://www.call2all.co.il/ym/api/RunTzintuk?token=${encodeURIComponent(config.token)}${callerIdParam}&TzintukTimeOut=9&sayInfoOnAnswer=true&phones=tzl:${encodeURIComponent(config.listName)}`;
            await ymFetch(tzintukUrl);

            targetElement.innerText = "✅ שיחה יצאה!";
            targetElement.style.color = "green";
        } catch (e) {
            targetElement.innerText = "❌ שגיאה בחיוג";
            console.error("Yemot API Error:", e);
        }
        resetElement(targetElement, originalText);
    }

    function resetElement(element, text) {
        setTimeout(() => {
            element.innerText = text; element.style.pointerEvents = "auto"; element.style.color = "";
        }, 3000);
    }

    // ==========================================
    // 6. סריקת DOM ויעילות (TreeWalker + Observer)
    // ==========================================
    const PHONE_REGEX = /(?:(?:(\+?972|\b0)(?:[-.\s]?\d){8,9})|\b(1[78]00|1599)(?:[-.\s]?\d){6}\b|\*\d{3,4}\b)/g;
    const IGNORE_TAGS = new Set(['SCRIPT', 'STYLE', 'NOSCRIPT', 'TEXTAREA', 'INPUT', 'SELECT', 'A', 'BUTTON']);

    function scanAndReplace(rootNode) {
        const walker = document.createTreeWalker(rootNode, NodeFilter.SHOW_TEXT, {
            acceptNode: function(node) {
                if (!node.parentNode || IGNORE_TAGS.has(node.parentNode.nodeName)) return NodeFilter.FILTER_REJECT;
                if (node.parentNode.hasAttribute('data-ym-dialer')) return NodeFilter.FILTER_REJECT;
                if (node.parentNode.closest && node.parentNode.closest('#ym-settings-modal, #ym-quick-dial-modal')) return NodeFilter.FILTER_REJECT;
                return PHONE_REGEX.test(node.nodeValue) ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_SKIP;
            }
        });

        const nodesToProcess = [];
        let currentNode;
        while (currentNode = walker.nextNode()) nodesToProcess.push(currentNode);

        nodesToProcess.forEach(node => {
            const text = node.nodeValue;
            const fragment = document.createDocumentFragment();
            let lastIndex = 0, match;
            PHONE_REGEX.lastIndex = 0;

            while ((match = PHONE_REGEX.exec(text)) !== null) {
                if (match.index > lastIndex) fragment.appendChild(document.createTextNode(text.slice(lastIndex, match.index)));
                const phoneNumber = match[0];
                const dialBadge = document.createElement('span');
                dialBadge.innerText = phoneNumber;
                dialBadge.title = "לחץ לחיוג מהיר באמצעות ימות המשיח";
                dialBadge.setAttribute('data-ym-dialer', 'true');
                dialBadge.style.cssText = "color: #0066cc; text-decoration: underline; cursor: pointer; font-weight: bold; background-color: #e6f2ff; padding: 0 3px; border-radius: 3px; margin: 0 1px;";
                dialBadge.addEventListener('click', (e) => { e.preventDefault(); e.stopPropagation(); triggerDial(phoneNumber, dialBadge); });
                fragment.appendChild(dialBadge);
                lastIndex = PHONE_REGEX.lastIndex;
            }
            if (lastIndex < text.length) fragment.appendChild(document.createTextNode(text.slice(lastIndex)));
            if (node.parentNode) node.parentNode.replaceChild(fragment, node);
        });
    }

    scanAndReplace(document.body);

    let debounceTimer = null;
    const observer = new MutationObserver((mutations) => {
        if (debounceTimer) clearTimeout(debounceTimer);
        debounceTimer = setTimeout(() => {
            mutations.forEach(mutation => {
                mutation.addedNodes.forEach(node => {
                    if (node.nodeType === Node.ELEMENT_NODE && !IGNORE_TAGS.has(node.nodeName)) {
                        if (node.id === 'ym-settings-modal' || node.id === 'ym-quick-dial-modal') return;
                        scanAndReplace(node);
                    } else if (node.nodeType === Node.TEXT_NODE && node.parentNode && !IGNORE_TAGS.has(node.parentNode.nodeName)) {
                        if (PHONE_REGEX.test(node.nodeValue)) scanAndReplace(node.parentNode);
                    }
                });
            });
        }, 400);
    });
    observer.observe(document.body, { childList: true, subtree: true });
})();
