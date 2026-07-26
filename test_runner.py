import unittest

def isValidIp(ip):
    if not isinstance(ip, str): return False
    parts = ip.strip().split('.')
    if len(parts) != 4: return False
    for p in parts:
        if not p.isdigit(): return False
        n = int(p)
        if n < 0 or n > 255: return False
        if len(p) > 1 and p.startswith('0'): return False
    return True

def ipToInt(ip):
    parts = [int(p) for p in ip.strip().split('.')]
    return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]

def intToIp(val):
    return f"{(val >> 24) & 255}.{(val >> 16) & 255}.{(val >> 8) & 255}.{val & 255}"

def maskToWildcard(input_str):
    if not input_str: return ''
    s = str(input_str).strip().lstrip('/')
    if s.isdigit():
        prefix = int(s)
        if 0 <= prefix <= 32:
            mask_int = 0 if prefix == 0 else ((0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF)
            wildcard_int = (~mask_int) & 0xFFFFFFFF
            return intToIp(wildcard_int)
    if isValidIp(s):
        mask_int = ipToInt(s)
        wildcard_int = (~mask_int) & 0xFFFFFFFF
        return intToIp(wildcard_int)
    return ''

# Python simulation test
def simulate_match(rules, pkt):
    for idx, r in enumerate(rules):
        # Protocol check
        if r['protocol'] != 'ip' and r['protocol'] != pkt['protocol']:
            continue
        # Source IP check
        if r['srcType'] == 'host' and r['srcIp'] != pkt['srcIp']:
            continue
        # Dst Port check
        if r['protocol'] in ['tcp', 'udp'] and r.get('dstPortOperator') == 'eq':
            if str(r.get('dstPort')) != str(pkt.get('dstPort')):
                continue
        return {'matched': True, 'index': idx + 1, 'action': r['action']}
    return {'matched': False, 'implicitDeny': True, 'action': 'deny'}

class TestACLGeneratorCore(unittest.TestCase):

    def test_wildcard_conversion(self):
        self.assertEqual(maskToWildcard("255.255.255.0"), "0.0.0.255")
        self.assertEqual(maskToWildcard("255.255.240.0"), "0.0.15.255")
        self.assertEqual(maskToWildcard("24"), "0.0.0.255")

    def test_packet_simulation(self):
        rules = [
            {'protocol': 'tcp', 'srcType': 'host', 'srcIp': '192.168.1.50', 'dstPortOperator': 'eq', 'dstPort': '80', 'action': 'permit'},
            {'protocol': 'ip', 'srcType': 'any', 'action': 'deny'}
        ]
        res1 = simulate_match(rules, {'protocol': 'tcp', 'srcIp': '192.168.1.50', 'dstPort': '80'})
        self.assertTrue(res1['matched'])
        self.assertEqual(res1['index'], 1)
        self.assertEqual(res1['action'], 'permit')

        res2 = simulate_match(rules, {'protocol': 'tcp', 'srcIp': '10.0.0.1', 'dstPort': '80'})
        self.assertTrue(res2['matched'])
        self.assertEqual(res2['index'], 2)
        self.assertEqual(res2['action'], 'deny')

if __name__ == '__main__':
    unittest.main()
