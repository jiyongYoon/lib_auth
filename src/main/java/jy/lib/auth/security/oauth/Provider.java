package jy.lib.auth.security.oauth;

public enum Provider {
    APP("app"),
    GOOGLE("google"),
    KAKAO("kakao"),
    NAVER("naver"),
    ;

    Provider(String value) {
        this.value = value;
    }

    private final String value;

    public String getValue() {
        return value;
    }

    public static Provider getProvider(String provider) {
        for (Provider value : Provider.values()) {
            if (value.getValue().equals(provider)) {
                return value;
            }
        }
        throw new RuntimeException("provider does not exist!");
    }
}
