#  Defines FingerPrint and Result objets

#ADD PROPER GCD COMPARATOR
class Result:
    def __init__(self, category, params):
        self.category = category  # name of tests type
        self.params = params  # dictionnary containing the tests results for the category

    def __repr__(self):
        return self.category + str(self.params)

    # add test expression operators
    def __eq__(self, other):
        if (len(self.params) != len(other.params)):
            return False

        if self.params != other.params:
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
