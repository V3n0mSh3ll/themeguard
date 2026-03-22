from collections import deque


class AhoCorasick:

    __slots__ = ("_goto", "_fail", "_output", "_state_count")

    def __init__(self):
        self._goto = [{}]
        self._fail = [0]
        self._output = [[]]
        self._state_count = 1

    def add_pattern(self, pattern, pattern_id=None):
        if pattern_id is None:
            pattern_id = pattern
        state = 0
        for ch in pattern:
            if ch not in self._goto[state]:
                self._goto[state][ch] = self._state_count
                self._goto.append({})
                self._fail.append(0)
                self._output.append([])
                self._state_count += 1
            state = self._goto[state][ch]
        self._output[state].append(pattern_id)

    def build(self):
        queue = deque()
        for ch, s in self._goto[0].items():
            self._fail[s] = 0
            queue.append(s)

        while queue:
            r = queue.popleft()
            for ch, s in self._goto[r].items():
                queue.append(s)
                state = self._fail[r]
                while state != 0 and ch not in self._goto[state]:
                    state = self._fail[state]
                self._fail[s] = self._goto[state].get(ch, 0)
                if self._fail[s] == s:
                    self._fail[s] = 0
                self._output[s] = self._output[s] + self._output[self._fail[s]]

    def search(self, text):
        state = 0
        results = []
        for i, ch in enumerate(text):
            while state != 0 and ch not in self._goto[state]:
                state = self._fail[state]
            state = self._goto[state].get(ch, 0)
            for pattern_id in self._output[state]:
                results.append((i, pattern_id))
        return results

    def search_first(self, text):
        state = 0
        for i, ch in enumerate(text):
            while state != 0 and ch not in self._goto[state]:
                state = self._fail[state]
            state = self._goto[state].get(ch, 0)
            if self._output[state]:
                return (i, self._output[state][0])
        return None

    def has_match(self, text):
        state = 0
        for ch in text:
            while state != 0 and ch not in self._goto[state]:
                state = self._fail[state]
            state = self._goto[state].get(ch, 0)
            if self._output[state]:
                return True
        return False
