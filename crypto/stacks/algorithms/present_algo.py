# coding: utf-8

s_box = (0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2)
p_layer_order = [0, 16, 32, 48, 1, 17, 33, 49, 2, 18, 34, 50, 3, 19, 35, 51, 4, 20, 36, 52, 5, 21, 37, 53, 6, 22, 38, 54, 7, 23, 39, 55, 8, 24, 40, 56, 9, 25, 41, 57, 10, 26, 42, 58, 11, 27, 43, 59, 12, 28, 44, 60, 13, 29, 45, 61, 14, 30, 46, 62, 15, 31, 47, 63]

class Present:
    def __init__(self, key):
        self.key = key
        self.round_limit = 32

    def _round_function(self, state, key):
        new_state = state ^ key
        state_nibs = []
        for x in range(0, 64, 4):
            nib = (new_state >> x) & 0xF
            state_nibs.append(s_box[nib])
        
        state_bits = []
        for y in state_nibs:
            state_bits += [1 if t == '1' else 0 for t in format(y, '04b')[::-1]]
        
        state_p_layer = [0 for _ in range(64)]
        for p_index, std_bits in enumerate(state_bits):
            state_p_layer[p_layer_order[p_index]] = std_bits

        round_output = 0
        for index, ind_bit in enumerate(state_p_layer):
            round_output += (ind_bit << index)
        
        return round_output

    def _key_function_80(self, key, round_count):
        r = [1 if t == '1' else 0 for t in format(key, '080b')[::-1]]
        h = r[-61:] + r[:-61]
        
        round_key_int = 0
        for index, ind_bit in enumerate(h):
            round_key_int += (ind_bit << index)
        
        upper_nibble = s_box[round_key_int >> 76]
        xor_portion = ((round_key_int >> 15) & 0x1F) ^ round_count
        return (round_key_int & 0x0FFFFFFFFFFFFFF07FFF) + (upper_nibble << 76) + (xor_portion << 15)

    def encrypt(self, plain_text):
        """Generates the masked PRG output."""
        key_schedule = []
        current_round_key = self.key
        round_state = plain_text
        
        for rnd_cnt in range(self.round_limit):
            key_schedule.append(current_round_key >> 16)
            current_round_key = self._key_function_80(current_round_key, rnd_cnt + 1)
            
        for rnd in range(self.round_limit - 1):
            round_state = self._round_function(round_state, key_schedule[rnd])
            
        round_state ^= key_schedule[31]
        return round_state