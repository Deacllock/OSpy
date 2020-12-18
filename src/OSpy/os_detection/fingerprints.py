# Defines FingerPrint and Result class


class Result:
    def __init__(self, category, params):
        self.category = category
        self.params = params

    def __repr__(self):
        return self.category + str(self.params)

    def _parse_expression(self, x, p_list):
        if type(p_list) is not list:
            p_list = [p_list]

        for p in p_list:
            if '-' in p:
                bounds = p.split('-')
                if int(x, 16) < int(bounds[0], 16) or int(x, 16) > int(bounds[1], 16):
                    return False
            
            elif '>' in p: 
                bound = p.split('>')
                if int(x, 16) <= int(bound[1], 16):
                    return False

            elif '<' in p:
                bound = p.split('<')
                print(bound)
                if int(x, 16) >= int(bound[1], 16):
                    return False

            else:
                if x != p:
                    return False

        return True

    def __eq__(self, other):
        if (len(self.params) != len(other.params)):
            return False

        for p in self.params:
            if not p in other.params:
                return False

            if p == 'T' or p == 'SS':
                continue

            elif p == 'GCD' or p == 'SP' or p == 'ISR':
                if self._parse_expression(self.params[p], other.params[p]) is not True:
                    return False

            elif self.params[p] != other.params[p]:
                return False

        return True


class FingerPrint:
    def __init__(self, name, results):
        self.name = name
        self.results = results  # list of tests results

    def __repr__(self):
        ret = self.name
        for r in self.results:
            ret += '\n' + str(r)
        return ret + '\n'

    def __eq__(self, other):
        if (len(self.results) != len(other.results)):
            return False

        for i in range(len(self.results)):
            if not (self.results[i] == other.results[i]):
                return False
        return True
