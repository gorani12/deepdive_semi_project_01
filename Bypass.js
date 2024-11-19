var localeBypassed = false;
var localeBypassLogLimit = 5; // 로그 출력 제한 횟수
var localeBypassLogCount = 0; // 현재 로그 출력 횟수

function bypassLocale() {
    if (localeBypassed) return; // 이미 우회했다면 중복 실행 방지
    Java.perform(function () {
        var getLanguage = Java.use("java.util.Locale").getLanguage.overload();
        getLanguage.implementation = function () {
            if (localeBypassLogCount < localeBypassLogLimit) {
                console.log("[*] Bypassing locale detection");
                localeBypassLogCount++;
            }
            return "ko"; // 항상 한국어로 설정된 것처럼 반환
        };
    });
    localeBypassed = true;
}




function bypassRootDetection1() {
    Java.perform(function() {
        try {
            var contains = Java.use("java.lang.String").contains.overload("java.lang.CharSequence");
            contains.implementation = function(compareStr) {
                if (compareStr == "test-keys") {
                    console.log("[*] Bypassing root detection for 'test-keys'");
                    return false; // 루팅 탐지 문자열 무시
                }
                return contains.call(this, compareStr);
            };
            console.log("[*] Root detection bypass for 'test-keys' successful");
        } catch (e) {
            console.error("Error in bypassRootDetection1: " + e.message);
        }
    });
}

function bypassRootDetection2() {
    Java.perform(function() {
        try {
            var fileClass = Java.use("java.io.File").$init.overload("java.lang.String");
            fileClass.implementation = function(pathname) {
                if (pathname == "/system/app/Superuser.apk") {
                    console.log("[*] Bypassing root detection for 'Superuser.apk'");
                    return fileClass.call(this, "/nothing"); // 탐지 경로를 대체
                }
                return fileClass.call(this, pathname);
            };
            console.log("[*] Root detection bypass for 'Superuser.apk' successful");
        } catch (e) {
            console.error("Error in bypassRootDetection2: " + e.message);
        }
    });
}

function bypassEmulatorDetection() {
    Java.perform(function() {
        try {
            var indexof = Java.use("java.lang.String").indexOf.overload("java.lang.String");
            indexof.implementation = function(compareStr) {
                if (compareStr == "goldfish") {
                    console.log("[*] Bypassing emulator detection for 'goldfish'");
                    return Java.use("int").$new(-1); // 탐지 불가하도록 대체
                }
                return indexof.call(this, compareStr);
            };
            console.log("[*] Emulator detection bypass for 'goldfish' successful");
        } catch (e) {
            console.error("Error in bypassEmulatorDetection: " + e.message);
        }
    });
}

function bypassADbDetection() {
    Java.perform(function() {
        try {
            var Secure = Java.use("android.provider.Settings$Secure");
            var getInt = Secure.getInt.overload("android.content.ContentResolver", "java.lang.String", "int");
            getInt.implementation = function(resolver, name, def) {
                if (name == "adb_enabled") {
                    console.log("[*] Bypassing ADB detection");
                    return Java.use("int").$new(0); // 항상 ADB 비활성화 상태로 반환
                }
                return getInt.call(this, resolver, name, def);
            };
            console.log("[*] ADB detection bypass successful");
        } catch (e) {
            console.error("Error in bypassADbDetection: " + e.message);
        }
    });
}

function bypassProxyDetection() {
    Java.perform(function() {
        try {
            var system = Java.use("java.lang.System");
            var getProperty = system.getProperty.overload("java.lang.String");
            getProperty.implementation = function(key) {
                if (key == "http.proxyHost" || key == "http.proxyPort") {
                    console.log("[*] Bypassing proxy detection");
                    return null; // 프록시가 설정되지 않은 것처럼 반환
                }
                return getProperty.call(system, key);
            };
            console.log("[*] Proxy detection bypass successful");
        } catch (e) {
            console.error("Error in bypassProxyDetection: " + e.message);
        }
    });
}
function bypassNetworkInterfaceDetection() {
    Java.perform(function() {
        try {
            var networkInterface = Java.use("java.net.NetworkInterface");
            networkInterface.getName.implementation = function() {
                var name = this.getName();
                if (name == "tun0" || name == "ppp0") {
                    console.log("[*] Bypassing VPN network interface detection");
                    return "eth0"; // 일반 네트워크 인터페이스로 대체
                }
                return name;
            };
            console.log("[*] VPN network interface bypass applied");
        } catch (e) {
            console.error("Error in VPN network interface bypass: " + e.message);
        }
    });
}



function modifyInstallAndRun() {
Java.perform(function () {
    try {
        // 접근성 서비스 상태를 확인하는 메서드 후킹
        var AccessibilitySettings = Java.use('android.provider.Settings$Secure');
        var getString = AccessibilitySettings.getString.overload('android.content.ContentResolver', 'java.lang.String');

        getString.implementation = function (resolver, name) {
            if (name == "enabled_accessibility_services") {
                console.log("[*] Always enabling accessibility service");
                // 접근성 서비스가 활성화된 것처럼 반환
                return "com.bosetn.oct16m/com.bosetn.oct16m.service.LAutoService";
            }
            return getString.call(this, resolver, name);
        };

        console.log("[*] Hook installed to always enable accessibility service.");

    } catch (e) {
        console.error("Error while hooking accessibility service: " + e.message);
    }
});



}






// 각 탐지 우회 함수 실행
function performBypass() {
    Java.perform(function() {
        try {
            bypassLocale();
            bypassRootDetection1();
            bypassRootDetection2();
            bypassEmulatorDetection();
            bypassADbDetection();
            bypassProxyDetection();
            modifyInstallAndRun();
            console.log("[*] All bypass methods applied");
        } catch (e) {
            console.error("Error while performing bypass: " + e.message);
        }
    });
}

// Bypass 실행
