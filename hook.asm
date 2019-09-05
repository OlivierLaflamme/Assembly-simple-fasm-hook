include 'win32ax.inc'


start:

     invoke LoadLibrary,'kernel32.dll'
     invoke GetProcAddress,eax,'Sleep'
     test eax,eax
     je @f

     push Stub
     push eax
     push ExecuteHook
     call InstallHook


     invoke Sleep,1000; when this API is called the function ExecuteHook is executed instead !!
     invoke Sleep,1000
     invoke Sleep,1000
     @@:
     invoke ExitProcess,0


     proc ExecuteHook, dwMilliseconds:DWORD
     invoke MessageBox,0,'Function API Sleep Hooked !','Hooked',MB_OK
     push [dwMilliseconds]
     mov eax,Stub
     call eax
     ret
     endp


 proc InstallHook uses ebx edi esi, hookProc:DWORD, target:DWORD, pStub:DWORD
 locals
 lpflOldProtect dd ?
 endl

 mov edi, [target]
 mov ebx, [pStub]

 invoke VirtualProtect, edi,5, PAGE_EXECUTE_READWRITE, addr lpflOldProtect
 invoke RtlMoveMemory, ebx, edi,5

 mov eax, [hookProc]
 sub eax, edi
 sub eax, 5
 mov byte [edi],0xe9
 mov [edi + 1], eax


 invoke VirtualProtect, edi,5,addr lpflOldProtect,[lpflOldProtect]
 mov esi, ebx
 add esi,5

 sub edi, ebx
 sub edi, 5

 mov byte [esi],0xe9
 mov [esi +1], edi
 ret
 endp

 Stub rb 10

.end start
