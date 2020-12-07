class Result:
    def __init__(self, category, params):
        self.category = category
        self.params = params #dictionnary containing the tests results for the category

    def __repr__(self):
        return self.category + str(self.params)

class FingerPrint:
    def  __init__(self, name, results):
        self.name = name
        self.results = results

    def __repr__(self):
        ret = self.name
        for r in self.results:
            ret += '\n' + str(r) 
        return ret + '\n'
