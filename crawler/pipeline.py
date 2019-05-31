class Pipeline():
    
    def __init__(self):
        pass

    def data_persistent(self,  data):
        for k, v in data.items():
            print(k + ' : ' + v)