package be.vdab.beveiligd.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

@Configuration
public class SecurityConfig {
    private static final String MANAGER = "manager";
    private static final String HELPDESKMEDEWERKER = "helpdeskmedewerker";
    private static final String MAGAZIJNER = "magazijner";
    private final DataSource dataSource;

    public SecurityConfig(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    @Bean
    /*public InMemoryUserDetailsManager maakPrincipals() {
        var joe = User.withUsername("joe")
                .password("{noop}theboss")
                .authorities(MANAGER)
                .build();
        var averell = User.withUsername("averell")
                .password("{noop}hungry")
                .authorities(HELPDESKMEDEWERKER,MAGAZIJNER)
                .build();
        return new InMemoryUserDetailsManager(joe,averell);
    }*/
    public JdbcUserDetailsManager maakPrincipals() {
        var manager = new JdbcUserDetailsManager(dataSource);
        manager.setUsersByUsernameQuery(
                """
                        select naam as username, paswoord as password, actief as enabled
                        from gebruikers where naam = ?
                        """
        );
        manager.setAuthoritiesByUsernameQuery(
                """
                        select gebruikers.naam as username, rollen.naam as authorities 
                        from gebruikers inner join gebruikersrollen on gebruikers.id =
                        gebruikersrollen.gebruikerId inner join rollen on rollen.id = 
                        gebruikersrollen.rolId where gebruikers.naam = ?
                        """
        );
        return manager;
    }
    @Bean
    public WebSecurityCustomizer configure(AuthenticationManagerBuilder auth) {
        return (web) -> web.ignoring().mvcMatchers("/images/**", "/css/**", "/js/**");
    }
    @Bean
    public SecurityFilterChain geefRechten(HttpSecurity http) throws Exception {
        http.logout(logout -> logout.logoutSuccessUrl("/"));
        http.formLogin(login -> login.loginPage("/login"));
        http.authorizeRequests(requests -> requests
                .mvcMatchers("/offertes/**").hasAuthority(MANAGER)
                .mvcMatchers("/werknemers/**").hasAnyAuthority(MAGAZIJNER,HELPDESKMEDEWERKER)
                .mvcMatchers("/", "/login").permitAll()
                .mvcMatchers("/**").authenticated());
        return http.build();
    }
}
