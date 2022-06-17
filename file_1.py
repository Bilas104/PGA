from datetime import datetime

class user(object):
    def __init__(self, usrname, pwd):
        self.usrname = usrname
        self.curr_pwd = pwd
        self.old_pwd = []
        self.dur = []
        self.creation_time = datetime.now().time()
        self.pwd_set_time = self.creation_time
        self.login_time = None
        self.last_login = None
        self.origin = {}
        self.ISP = {}
        self.country = {}

    def login(self, origin, ISP, country):
        if self.login_time != None:
            self.last_login = self.login_time

        else:
            self.last_login = datetime.now().time()

        self.login_time = datetime.now().time()
        self.origin[origin] = [ISP, country]
        
        if self.ISP not in self.ISP.keys():
            self.ISP[ISP] = 1
        
        else:
            self.ISP[ISP] += 1

        if self.country not in self.country.keys():
            self.country[country] = 1
        
        else:
            self.country[country] += 1

    def pwd_change(self, pwd, new_pwd):
        self.old_pwd.append(pwd)
        self.pwd = new_pwd
        self.dur.append(datetime.now().time() - self.pwd_set_time)
        self.pwd_set_time = datetime.now().time()

    def getUsrname(self):
        return self.usrname

    def getPwd(self):
        return self.curr_pwd

    def getOrigin(self):
        return self.origin

    def getISP(self):
        return self.ISP

    def getCountry(self):
        return self.country
        

class login_attempt_log(object):
    def __init__(self, origin, ISP, country, usrname, pwd, outcome):
        self.origin = origin
        self.time = datetime.now().time()
        self.usrname = usrname
        self.pwd = pwd
        self.outcome = outcome
        self.ISP = ISP
        self.country = country

class failed_attempt_log(login_attempt_log):
    def __init__(self, origin, ISP, country, usrname, pwd, outcome):
        super().__init__(origin, ISP, country, usrname, pwd, outcome)
        self.prev_time = None
        self.count = 0
        self.freq = []
        self.attempted_pwd = []

    def update(self):
        self.count += 1
        self.attempted_pwd = self.pwd

        if self.count == 1:
            self.prev_time = self.time
            self.freq.append(0)
        
        else:
            self.freq.append(1/(self.time - self.prev_time))
            self.prev_time = self.time

    # Calculate deviance on user's origin
    def origin_deviance(self, usr):
        IPs = usr.getOrigin()
        seen_ISPs = usr.getISP()
        total_ISPs = len(seen_ISPs.keys())

        IPs_from_ISP = 0
        for k in IPs.keys():
            if IPs[k][0] == self.origin:
                IPs_from_ISP += 1

        seen_countries = usr.getCountry()
        total_countries = len(seen_countries.keys())

        IPs_from_country = 0
        for k in IPs.keys():
            if IPs[k][0] == self.origin:
                IPs_from_country += 1

        if self.ISP in seen_ISPs.keys():
            # deviance = Prob(unseen IP)
            dev = (1 / IPs_from_ISP) * (usr.ISP[self.ISP] / total_ISPs)
            return dev

        if self.country in seen_countries.keys():
            # deviance = Prob(unseen IP)
            dev = (1 / IPs_from_country) * (usr.country[self.countries] / total_countries)
            return dev
