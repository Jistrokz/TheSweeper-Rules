rule Password_File{
    meta:
        author = "Kartavya"
        description = "There were files found titled password.txt "
	version = "0.1"
    strings:
        $c1 = "OpenProcess"
        $c2 = "VirtualAllocEx"
        $c3 = "NtWriteVirtualMemory"
        $c4 = "WriteProcessMemory"
        $c5 = "CreateRemoteThread"
        $c6 = "CreateThread"
        $c7 = "OpenProcess"
    condition:
        $c1 and $c2 and ( $c3 or $c4 ) and ( $c5 or $c6 or $c7 )
}