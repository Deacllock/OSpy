class HostError(ErrorType):
    pass

class Host:
    def __init__(self, ip, name=None, os=None):
        self.ip = ip
        self.name = name
        self.os = os

    #Convert the host into string (print(host))
    def __repr__(self):
        return 'str description for Host'
    #careful with os and name that can be null, you could raise a custom exception (raise HostError())

h = Host('ip')
print(h)
