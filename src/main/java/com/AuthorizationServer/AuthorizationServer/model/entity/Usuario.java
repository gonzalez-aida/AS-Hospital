package com.AuthorizationServer.AuthorizationServer.model.entity;

import jakarta.persistence.*;
import lombok.Data;

@Data
@Entity
@Table(name = "usuario")
public class Usuario {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id_usuario")
    private Integer idUsuario;
    
    @Column(name = "correo", unique = true, length = 200)
    private String correo;
    
    @Column(name = "contrasena", length = 255)
    private String contrasena;
    
    @Enumerated(EnumType.STRING)
    @Column(name = "rol", length = 20)
    private Rol rol = Rol.MEDICO;
    
    @Enumerated(EnumType.STRING)
    @Column(name = "estado", nullable = false)
    private Estado estado = Estado.ACTIVO;
    
    public enum Rol {
        MEDICO, PACIENTE, ADMIN
    }
    
    public enum Estado {
        ACTIVO, INACTIVO
    }
}