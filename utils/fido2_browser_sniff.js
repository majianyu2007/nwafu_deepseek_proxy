// ==UserScript==
// @name         CAS FIDO2 WebAuthn Assertion Sniffer
// @namespace    https://authserver.nwafu.edu.cn
// @match        https://authserver.nwafu.edu.cn/*
// @grant        none
// @run-at       document-start
// ==/UserScript==

(function() {
    'use strict';

    var capturedAssertion = null;
    var capturedRequestBody = null;
    var submitBlocked = false;

    function ab2b64(buf) {
        var bytes = new Uint8Array(buf);
        var bin = '';
        for (var i = 0; i < bytes.length; i++) {
            bin += String.fromCharCode(bytes[i]);
        }
        return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    }

    function hex(bytes) {
        return Array.from(bytes).map(function(b) { return b.toString(16).padStart(2,'0'); }).join(' ');
    }

    function b64urlDecode(s) {
        s = s.replace(/-/g, '+').replace(/_/g, '/');
        while (s.length % 4) s += '=';
        var raw = atob(s);
        var bytes = new Uint8Array(raw.length);
        for (var i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
        return bytes;
    }

    function buildReport() {
        var lines = [];
        lines.push('========== FIDO2 CAPTURED DATA ==========');
        lines.push('');

        if (capturedRequestBody) {
            lines.push('--- full responseJson (form field value) ---');
            lines.push(JSON.stringify(capturedRequestBody, null, 2));
            lines.push('');
        }

        if (capturedAssertion) {
            lines.push('--- assertion (credential field) ---');
            lines.push(JSON.stringify(capturedAssertion, null, 2));
            lines.push('');
            lines.push('--- decoded clientDataJSON ---');
            lines.push(new TextDecoder().decode(b64urlDecode(capturedAssertion.response.clientDataJSON)));
            lines.push('');
            lines.push('--- decoded authenticatorData (hex) ---');
            var ad = b64urlDecode(capturedAssertion.response.authenticatorData);
            lines.push(hex(ad));
            lines.push('  rpIdHash (32B): ' + hex(ad.slice(0,32)));
            lines.push('  flags: 0x' + ad[32].toString(16).padStart(2,'0'));
            lines.push('  counter: ' + (ad[33]<<24|ad[34]<<16|ad[35]<<8|ad[36]));
            lines.push('');
            lines.push('--- signature (hex) ---');
            lines.push(hex(b64urlDecode(capturedAssertion.response.signature)));
            lines.push('');
            lines.push('--- startAssertion response ---');
            var sa = sessionStorage.getItem('__fido2_sniff_startAssertion');
            if (sa) lines.push(sa);
        }

        lines.push('========== END ==========');
        return lines.join('\n');
    }

    // ---- Hook navigator.credentials.get ----
    var origGet = navigator.credentials.get.bind(navigator.credentials);
    navigator.credentials.get = function(options) {
        if (options && options.publicKey) {
            return origGet(options).then(function(response) {
                capturedAssertion = {
                    id: response.id,
                    type: response.type,
                    response: {
                        authenticatorData: ab2b64(response.response.authenticatorData),
                        clientDataJSON: ab2b64(response.response.clientDataJSON),
                        signature: ab2b64(response.response.signature),
                    },
                };
                if (response.response.userHandle) {
                    capturedAssertion.response.userHandle = ab2b64(response.response.userHandle);
                }
                try {
                    capturedAssertion.clientExtensionResults = response.getClientExtensionResults();
                } catch(e) {}

                return response;
            });
        }
        return origGet(options);
    };

    // ---- Hook XHR to capture startAssertion request/response ----
    var origXHR = window.XMLHttpRequest;
    window.XMLHttpRequest = function() {
        var xhr = new origXHR();
        var origOpen = xhr.open;
        var origSend = xhr.send;
        xhr.open = function(method, url) {
            xhr._url = url;
            xhr._method = method;
            return origOpen.apply(xhr, arguments);
        };
        xhr.send = function(body) {
            if (xhr._url && xhr._url.indexOf('startAssertion') > -1) {
                xhr.addEventListener('load', function() {
                    sessionStorage.setItem('__fido2_sniff_startAssertion',
                        'REQUEST: ' + body + '\nRESPONSE: ' + xhr.responseText);
                });
            }
            return origSend.apply(xhr, arguments);
        };
        return xhr;
    };

    // ---- Intercept form submit: block, show floating div, let user copy ----
    var _realSubmit = HTMLFormElement.prototype.submit;
    HTMLFormElement.prototype.submit = function() {
        var rj = document.getElementById('responseJson-fido');
        if (rj && rj.value && !this.__fido2_blocked) {
            this.__fido2_blocked = true;
            try { capturedRequestBody = JSON.parse(rj.value); } catch(e) {}
            var report = buildReport();
            localStorage.setItem('__fido2_report', report);
            navigator.clipboard.writeText(report);

            // Floating div that blocks nothing visually but stays on screen
            var div = document.createElement('div');
            div.style.cssText = 'position:fixed;top:0;left:0;right:0;bottom:0;z-index:2147483647;background:rgba(0,0,0,0.9);display:flex;align-items:center;justify-content:center;';
            var inner = document.createElement('div');
            inner.style.cssText = 'background:#1a1a2e;color:#0f0;padding:20px;border:2px solid #e94560;max-width:750px;max-height:85vh;overflow:auto;font:12px monospace;border-radius:8px;white-space:pre-wrap;word-break:break-all;';
            inner.textContent = report;
            var btn = document.createElement('button');
            btn.textContent = 'Copied! Click to continue login';
            btn.style.cssText = 'display:block;margin-top:12px;background:#e94560;color:#fff;border:none;padding:10px 24px;font-size:14px;cursor:pointer;border-radius:6px;';
            btn.onclick = function() {
                div.remove();
                _realSubmit.call(this._form);
            }.bind({_form: this});
            inner.appendChild(btn);
            div.appendChild(inner);
            document.body.appendChild(div);
            return; // BLOCK submit
        }
        return _realSubmit.apply(this, arguments);
    };

    console.log('[FIDO2 Sniffer] Ready. Click 生物识别 → complete fingerprint → floating panel appears.');
})();
