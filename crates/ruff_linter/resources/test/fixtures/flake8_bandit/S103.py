import os
import stat

# ============================================================================
# BASIC PERMISSION TESTS
# ============================================================================
keyfile = "foo"
os.chmod("/etc/passwd", 0o227)  # Error - world-writable
os.chmod("/etc/passwd", 0o7)    # Error - world-writable and executable
os.chmod("/etc/passwd", 0o664)  # OK
os.chmod("/etc/passwd", 0o777)  # Error - world-writable
os.chmod("/etc/passwd", 0o770)  # Error - overly permissive group
os.chmod("/etc/passwd", 0o776)  # Error - world-writable
os.chmod("/etc/passwd", 0o760)  # OK
os.chmod("~/.bashrc", 511)      # Error - 511 = 0o777
os.chmod("/etc/hosts", 0o777)   # Error - world-writable
os.chmod("/tmp/oh_hai", 0x1FF)  # Error - 0x1FF = 511 = 0o777
os.chmod("/etc/passwd", stat.S_IRWXU)  # OK - 0o700
os.chmod(keyfile, 0o777)        # Error - world-writable
os.chmod(keyfile, 0o7 | 0o70 | 0o700)  # Error - results in 0o777
os.chmod(keyfile, stat.S_IRWXO | stat.S_IRWXG | stat.S_IRWXU)  # Error - 0o777
os.chmod("~/hidden_exec", stat.S_IXGRP)  # Error - group executable only (unusual)
os.chmod("~/hidden_exec", stat.S_IXOTH)  # Error - world-executable
os.chmod("/etc/passwd", stat.S_IWOTH)    # Error - world-writable
os.chmod("/etc/passwd", 0o100000000)     # Error - large number, should be masked

# ============================================================================
# LARGE NUMBER TESTS (testing the overflow fix)
# ============================================================================

# These should NOT trigger violations after masking
os.chmod("/tmp/large1", 0o777777 & 0o700)   # Should be 0o700 (safe)
os.chmod("/tmp/large2", 0o777777 & 0o600)   # Should be 0o600 (safe)
os.chmod("/tmp/large3", 0o777777 & 0o644)   # Should be 0o644 (safe)
os.chmod("/tmp/large4", 0o777777 & 0o755)   # Should be 0o755 (world-executable)
os.chmod("/tmp/large5", 0o1000000 & 0o600)  # Should be 0o600 (safe)

# These should still trigger violations after masking
os.chmod("/tmp/large_bad1", 0o777777 & 0o777)  # Should be 0o777 (world-writable)
os.chmod("/tmp/large_bad2", 0o777777 & 0o666)  # Should be 0o666 (world-writable)
os.chmod("/tmp/large_bad3", 0o1777777 & 0o4755) # Should be 0o4755 (setuid)

# Very large numbers that should be masked down
os.chmod("/tmp/huge1", 0o12345670123)          # Should be masked to valid range
os.chmod("/tmp/huge2", 0o77777777777)          # Should be masked to valid range

# ============================================================================
# BITWISE OPERATION TESTS
# ============================================================================

# Safe bitwise operations
os.chmod("/tmp/bit_safe1", 0o700 | 0o040)      # 0o740 (safe)
os.chmod("/tmp/bit_safe2", 0o600 | 0o044)      # 0o644 (safe)
os.chmod("/tmp/bit_safe3", 0o755 & 0o644)      # 0o644 (safe)
os.chmod("/tmp/bit_safe4", 0o777 ^ 0o133)      # 0o644 (safe)
os.chmod("/tmp/bit_safe5", 0o644 << 0)         # 0o644 (safe)
os.chmod("/tmp/bit_safe6", 0o1644 >> 3)        # 0o644 (safe)

# Dangerous bitwise operations
os.chmod("/tmp/bit_bad1", 0o600 | 0o066)       # 0o666 (world-writable)
os.chmod("/tmp/bit_bad2", 0o644 | 0o111)       # 0o755 (world-executable)
os.chmod("/tmp/bit_bad3", 0o700 | 0o077)       # 0o777 (world-writable)
os.chmod("/tmp/bit_bad4", 0o4000 | 0o755)      # 0o4755 (setuid)
os.chmod("/tmp/bit_bad5", 0o2000 | 0o644)      # 0o2644 (setgid)
os.chmod("/tmp/bit_bad6", 0o600 << 1)          # 0o1400 (if shift allowed, could be dangerous)

# Complex nested operations
os.chmod("/tmp/complex1", (0o700 | 0o040) & 0o744)   # Should be safe
os.chmod("/tmp/complex2", (0o600 | 0o066) | 0o111)   # Should be dangerous
os.chmod("/tmp/complex3", 0o777 & (0o644 | 0o111))   # Should be dangerous

# ============================================================================
# STAT MODULE CONSTANT TESTS
# ============================================================================

# Safe stat combinations
os.chmod("/tmp/stat_safe1", stat.S_IRUSR | stat.S_IWUSR)  # 0o600
os.chmod("/tmp/stat_safe2", stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP)  # 0o640
os.chmod("/tmp/stat_safe3", stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)  # 0o644
os.chmod("/tmp/stat_safe4", stat.S_IRWXU | stat.S_IRGRP)  # 0o740

# Dangerous stat combinations
os.chmod("/tmp/stat_bad1", stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)  # 0o777
os.chmod("/tmp/stat_bad2", stat.S_IRUSR | stat.S_IWUSR | stat.S_IWOTH)  # 0o602 (world-writable)
os.chmod("/tmp/stat_bad3", stat.S_ISUID | stat.S_IRWXU)                 # 0o4700 (setuid)
os.chmod("/tmp/stat_bad4", stat.S_ISGID | stat.S_IRWXU | stat.S_IRWXG)  # 0o2770 (setgid)
os.chmod("/tmp/stat_bad5", stat.S_IRWXU | stat.S_IXOTH)                 # 0o701 (world-executable)
os.chmod("/tmp/stat_bad6", stat.S_IRWXU | stat.S_IRWXG)                 # 0o770 (overly permissive group)

# Mixed stat and octal
os.chmod("/tmp/mixed1", stat.S_IRWXU | 0o066)    # 0o766 (world-writable)
os.chmod("/tmp/mixed2", 0o700 | stat.S_IROTH)    # 0o704 (safe)
os.chmod("/tmp/mixed3", 0o4000 | stat.S_IRWXU)   # 0o4700 (setuid)

# ============================================================================
# UNARY OPERATION TESTS
# ============================================================================

# Bitwise NOT operations (these might be tricky)
os.chmod("/tmp/unary1", ~0o077)      # Should be safe (inverts to owner-only roughly)
os.chmod("/tmp/unary2", ~0o000)      # Should be dangerous (all bits set)

# Positive/negative unary
os.chmod("/tmp/unary3", +0o644)      # Should be safe (same as 0o644)
# os.chmod("/tmp/unary4", -0o644)    # Should error (negative permissions)

# ============================================================================
# EDGE CASES AND ERROR CONDITIONS
# ============================================================================

# Dynamic values (should not trigger - can't analyze statically)
mode = 0o777
os.chmod("/tmp/dynamic1", mode)

user_input = "777"
os.chmod("/tmp/dynamic2", int(user_input, 8))

def get_mode():
    return 0o777

os.chmod("/tmp/dynamic3", get_mode())

# Variables with stat constants (might not be analyzable)
dangerous_mode = stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO
os.chmod("/tmp/var_mode", dangerous_mode)

# ============================================================================
# DIFFERENT NUMBER FORMATS
# ============================================================================

# Decimal equivalents of dangerous octal numbers
os.chmod("/tmp/decimal1", 511)    # 511 = 0o777 (dangerous)
os.chmod("/tmp/decimal2", 438)    # 438 = 0o666 (dangerous)
os.chmod("/tmp/decimal3", 493)    # 493 = 0o755 (dangerous)
os.chmod("/tmp/decimal4", 420)    # 420 = 0o644 (safe)

# Hexadecimal equivalents
os.chmod("/tmp/hex1", 0x1FF)      # 0x1FF = 511 = 0o777 (dangerous)
os.chmod("/tmp/hex2", 0x1B6)      # 0x1B6 = 438 = 0o666 (dangerous)
os.chmod("/tmp/hex3", 0x1ED)      # 0x1ED = 493 = 0o755 (dangerous)
os.chmod("/tmp/hex4", 0x1A4)      # 0x1A4 = 420 = 0o644 (safe)

# ============================================================================
# GROUP PERMISSION EDGE CASES
# ============================================================================

# Test the group permission logic specifically
os.chmod("/tmp/group1", 0o770)    # Error - overly permissive group
os.chmod("/tmp/group2", 0o760)    # OK - group read/write only
os.chmod("/tmp/group3", 0o750)    # OK - group read/execute only
os.chmod("/tmp/group4", 0o740)    # OK - group read only
os.chmod("/tmp/group5", 0o070)    # Error - only group permissions, all set
os.chmod("/tmp/group6", 0o060)    # OK - only group read/write
os.chmod("/tmp/group7", 0o010)    # OK - only group execute

# ============================================================================
# SETUID/SETGID COMPREHENSIVE TESTS
# ============================================================================

# Various setuid combinations
os.chmod("/tmp/setuid1", 0o4755)   # Error - setuid + world-executable
os.chmod("/tmp/setuid2", 0o4750)   # Error - setuid + group-executable
os.chmod("/tmp/setuid3", 0o4700)   # Error - setuid + owner-only
os.chmod("/tmp/setuid4", 0o4644)   # Error - setuid + readable

# Various setgid combinations
os.chmod("/tmp/setgid1", 0o2755)   # Error - setgid + world-executable
os.chmod("/tmp/setgid2", 0o2750)   # Error - setgid + group-executable
os.chmod("/tmp/setgid3", 0o2700)   # Error - setgid + owner-only

# Both setuid and setgid
os.chmod("/tmp/both1", 0o6755)     # Error - both + world-executable
os.chmod("/tmp/both2", 0o6700)     # Error - both + owner-only

# Sticky bit (0o1000) - should this be flagged?
os.chmod("/tmp/sticky1", 0o1777)   # Error - sticky + world-writable
os.chmod("/tmp/sticky2", 0o1755)   # Error - sticky + world-executable
os.chmod("/tmp/sticky3", 0o1644)   # OK - sticky + safe permissions
