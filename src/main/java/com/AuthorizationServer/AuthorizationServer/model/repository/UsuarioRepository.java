package com.AuthorizationServer.AuthorizationServer.model.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.AuthorizationServer.AuthorizationServer.model.entity.Usuario;

public interface UsuarioRepository extends JpaRepository<Usuario, Integer> {

    Optional<Usuario> findByCorreoAndContrasena(String correo, String contrasena);

    Optional<Usuario> findByCorreo(String correo);

    boolean existsByCorreo(String correo);
}
