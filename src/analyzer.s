/*
Autor: Lulymito (Estudiante)
Curso: Arquitectura de Computadoras / Ensamblador ARM64
Práctica: Mini Cloud Log Analyzer - VARIANTE B
Fecha: 22 de abril de 2026
Descripción: Encuentra el código HTTP más frecuente desde stdin (uno por línea)
             usando únicamente syscalls Linux.
*/

.equ SYS_read,   63
.equ SYS_write,  64
.equ SYS_exit,   93
.equ STDIN_FD,    0
.equ STDOUT_FD,   1

.section .bss
    .align 4
buffer:         .skip 4096
num_buf:        .skip 32
counters:       .skip 400 * 4    // 400 posibles códigos (200-599)

.section .data
msg_titulo:     .asciz "=== Mini Cloud Log Analyzer - Variante B ===\n"
msg_resultado:  .asciz "Código más frecuente: "
msg_fin_linea:  .asciz "\n"
msg_empate:     .asciz " (empate, se muestra el menor código)\n"

.section .text
.global _start

_start:
    // Inicializar contadores a cero (400 posiciones)
    adrp x19, counters
    add x19, x19, :lo12:counters
    mov x20, #400
    mov x21, #0
init_loop:
    str w21, [x19], #4
    subs x20, x20, #1
    b.ne init_loop
    
    // Variables
    mov x22, #0        // número actual
    mov x23, #0        // tiene_dígitos
    mov x24, #0        // max_frecuencia
    mov x25, #0        // codigo_mas_frecuente

leer_bloque:
    mov x0, #STDIN_FD
    adrp x1, buffer
    add x1, x1, :lo12:buffer
    mov x2, #4096
    mov x8, #SYS_read
    svc #0

    cmp x0, #0
    beq fin_lectura
    blt salida_error

    mov x26, #0        // índice i = 0
    mov x27, x0        // total bytes

procesar_byte:
    cmp x26, x27
    b.ge leer_bloque

    adrp x1, buffer
    add x1, x1, :lo12:buffer
    ldrb w28, [x1, x26]
    add x26, x26, #1

    cmp w28, #10       // '\n'
    b.eq fin_numero

    cmp w28, #'0'
    b.lt procesar_byte
    cmp w28, #'9'
    b.gt procesar_byte

    // Acumular dígito
    mov x29, #10
    mul x22, x22, x29
    sub w28, w28, #'0'
    uxtw x28, w28
    add x22, x22, x28
    mov x23, #1
    b procesar_byte

fin_numero:
    cbz x23, reiniciar_numero
    
    // Clasificar código (solo válidos 200-599)
    mov x0, x22
    bl actualizar_contador

reiniciar_numero:
    mov x22, #0
    mov x23, #0
    b procesar_byte

fin_lectura:
    cbz x23, imprimir_reporte
    mov x0, x22
    bl actualizar_contador

imprimir_reporte:
    adrp x0, msg_titulo
    add x0, x0, :lo12:msg_titulo
    bl write_cstr

    adrp x0, msg_resultado
    add x0, x0, :lo12:msg_resultado
    bl write_cstr
    
    mov x0, x25
    bl print_uint
    
    adrp x0, msg_fin_linea
    add x0, x0, :lo12:msg_fin_linea
    bl write_cstr

salida_ok:
    mov x0, #0
    mov x8, #SYS_exit
    svc #0

salida_error:
    mov x0, #1
    mov x8, #SYS_exit
    svc #0

// -----------------------------------------------------------------------------
// actualizar_contador(x0 = codigo_http)
// Incrementa el contador para ese código y actualiza el más frecuente
// -----------------------------------------------------------------------------
actualizar_contador:
    // Validar rango 200-599
    cmp x0, #200
    b.lt actualizar_fin
    cmp x0, #599
    b.gt actualizar_fin
    
    // Calcular índice (código - 200)
    sub x1, x0, #200
    
    // Obtener puntero a contador
    adrp x2, counters
    add x2, x2, :lo12:counters
    add x2, x2, x1, lsl #2   // desplazamiento * 4
    
    // Incrementar contador
    ldr w3, [x2]
    add w3, w3, #1
    str w3, [x2]
    
    // Comparar con max_frecuencia
    uxtw x3, x3
    cmp x3, x24
    b.lt actualizar_fin
    b.gt nuevo_maximo
    
    // Empate: elegir el código MENOR
    cmp x0, x25
    b.ge actualizar_fin
    mov x25, x0
    b actualizar_fin
    
nuevo_maximo:
    mov x24, x3
    mov x25, x0

actualizar_fin:
    ret

// -----------------------------------------------------------------------------
// write_cstr(x0 = puntero a string terminado en '\0')
// -----------------------------------------------------------------------------
write_cstr:
    mov x9, x0
    mov x10, #0

wc_len_loop:
    ldrb w11, [x9, x10]
    cbz w11, wc_len_done
    add x10, x10, #1
    b wc_len_loop

wc_len_done:
    mov x1, x9
    mov x2, x10
    mov x0, #STDOUT_FD
    mov x8, #SYS_write
    svc #0
    ret

// -----------------------------------------------------------------------------
// print_uint(x0 = entero sin signo)
// -----------------------------------------------------------------------------
print_uint:
    cbnz x0, pu_convertir
    adrp x1, num_buf
    add x1, x1, :lo12:num_buf
    mov w2, #'0'
    strb w2, [x1]
    mov x0, #STDOUT_FD
    mov x2, #1
    mov x8, #SYS_write
    svc #0
    ret

pu_convertir:
    adrp x12, num_buf
    add x12, x12, :lo12:num_buf
    add x12, x12, #31
    mov w13, #0
    strb w13, [x12]

    mov x14, #10
    mov x15, #0

pu_loop:
    udiv x16, x0, x14
    msub x17, x16, x14, x0
    add x17, x17, #'0'

    sub x12, x12, #1
    strb w17, [x12]
    add x15, x15, #1

    mov x0, x16
    cbnz x0, pu_loop

    mov x1, x12
    mov x2, x15
    mov x0, #STDOUT_FD
    mov x8, #SYS_write
    svc #0
    ret
