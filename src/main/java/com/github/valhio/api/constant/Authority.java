package com.github.valhio.api.constant;

import org.springframework.security.core.GrantedAuthority;

public class Authority {

    public static final String[] USER_AUTHORITIES = {"READ"};
    public static final String[] HR_AUTHORITIES = {"READ", "UPDATE"};
    public static final String[] MANAGER_AUTHORITIES = {"READ", "UPDATE"};
    public static final String[] ADMIN_AUTHORITIES = {"READ", "CREATE", "UPDATE"};
    public static final String[] SUPER_ADMIN_AUTHORITIES = {"READ", "CREATE", "UPDATE", "DELETE"};

}
