
PUBLIC DisableWP
PUBLIC EnableWP

.code
DisableWP PROC
push rbp
mov rbp, rsp

push rdx
mov rdx, cr0
and rdx, 0FFFFFFFFFFFEFFFFh
mov cr0, rdx
pop rdx

pop rbp
ret
DisableWP ENDP

EnableWP PROC
push rbp
mov rbp, rsp

push rdx
mov rdx, cr0
or rdx, 0000000000010000h
mov cr0, rdx
pop rdx

pop rbp
ret
EnableWP ENDP
END