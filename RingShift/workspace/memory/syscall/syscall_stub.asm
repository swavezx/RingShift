.CODE
do_syscall PROC
    ; rcx = id, rdx = a1, r8 = a2, r9 = a3, [rsp+28h]= a4, [rsp+30h] = a5 ...
    mov r10, rdx        ; a1 → r10
    mov eax, ecx        ; id → eax
    mov rdx, r8         ; a2 → rdx
    mov r8,  r9         ; a3 → r8
    mov r9,  [rsp+28h]  ; a4 → r9  (war stack-arg1)
    ; a5+ bleiben auf Stack, aber jetzt um einen Slot verschoben:
    mov r11, [rsp+30h]
    mov [rsp+28h], r11
    mov r11, [rsp+38h]
    mov [rsp+30h], r11
    mov r11, [rsp+40h]
    mov [rsp+38h], r11
    syscall
    ret
do_syscall ENDP
END