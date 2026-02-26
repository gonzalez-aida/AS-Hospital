package com.AuthorizationServer.AuthorizationServer.service;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;

import com.AuthorizationServer.AuthorizationServer.model.entity.Usuario;
import com.AuthorizationServer.AuthorizationServer.model.repository.UsuarioRepository;

import java.util.Collections;

@Service 
public class UsuarioService implements UserDetailsService {

    private final UsuarioRepository usuarioRepository;

    @Autowired
    public UsuarioService(UsuarioRepository userRepository) {
        this.usuarioRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String correo) throws UsernameNotFoundException {
        Usuario user = usuarioRepository.findByCorreo(correo)
                .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado: " + correo));

        GrantedAuthority authority = new SimpleGrantedAuthority(user.getRol().name());

        return new org.springframework.security.core.userdetails.User(
            user.getCorreo(),          
            user.getContrasena(), 
            user.getEstado() == Usuario.Estado.ACTIVO,
            true, true, true, 
            Collections.singleton(authority)
        );
    }
}