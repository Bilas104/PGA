import numpy as np
import pandas as pd
import random
from randomtimestamp import randomtimestamp, random_date, random_time
from datetime import datetime
from cmath import exp
import enchant
import pandas as pd
from scipy.stats import entropy
from dateutil import parser


def strength_pwd(pwd):
    c_l = c_u = c_d = c_s = 0

    for ch in pwd:
        if ch.islower():
            c_l += 1

        elif ch.isupper():
            c_u += 1

        elif ch.isdigit():
            c_d += 1

        else:
            c_s += 1

    return c_l + 5 * c_u + 10 * c_d + 15 * c_s

def timezone(hour):
    if hour < 6:
        return 0
            
    elif hour < 10:
        return 1

    elif hour < 17:
        return 2

    elif hour < 21:
        return 3

    elif hour <= 23:
        return 4

def print_parameters(usr):
    print('Origin Deviance: ', failed_logs[usr].origin_deviance(usr_dict[usr]))
    print('Uncertainty due to timing: ', failed_logs[usr].uncertainty(usr_dict[usr]))
    print('Contextual Threat: ', failed_logs[usr].contextual_threat(usr_dict[usr]))
    print('Password Deviance: ', failed_logs[usr].pwd_deviance(usr_dict[usr]))
    print('Frequency Threat: ', failed_logs[usr].freq_threat())
    print('Behavorial Threat: ', failed_logs[usr].behavorial_threat(usr_dict[usr]))
    print('Risk from this attempt: ', failed_logs[usr].risk(usr_dict[usr]))
    print('Risk Capacity of User: ', failed_logs[usr].risk_capacity(usr_dict[usr]))
    failed_logs[usr].block(usr_dict[usr])
    print('User Blocked Status: ', usr_dict[usr].blocked)

def attempt(usr, origin, ISP, country, pwd, dt):
    if usr not in user_list:
        print('Invalid Username')
        return

    if usr_dict[usr].blocked == True:
        print("Blocked")
        return

    if pwd != usr_dict[usr].curr_pwd:
        failed_logs[usr].update(origin, ISP, country, pwd, dt)
        tz = timezone(dt.time().hour)
        usr_dict[usr].tz_login[tz][1] += 1
        print_parameters(usr)

    else:
        usr_dict[usr].login(origin, ISP, country, dt)

class user(object):
    def __init__(self, usrname, pwd, old_pwd = [], dur = []):
        self.usrname = usrname
        self.curr_pwd = pwd
        self.old_pwd = old_pwd
        self.dur = dur
        self.pwd_set_time = randomtimestamp(start_year = 2021, text = True)
        self.login_time = None
        self.prev_login_time = [] # stores times of successful logging 
        self.origin = {} # origin : [ISP, country]
        self.ISP = {} # ISP : no. of times it occurred
        self.country = {} # country : no. of times it occurred
        self.blocked = False
        self.tz_login = {new_list : [0, 0] for new_list in range(5)} # count of successful logging in particular timezones

    def login(self, origin, ISP, country, time):
        self.login_time = time
        self.prev_login_time.append(time)
        tz = timezone(time.time().hour)
        self.tz_login[tz][0] += 1

        self.origin[origin] = [ISP, country]
        
        if ISP not in self.ISP.keys():
            self.ISP[ISP] = 1
        
        else:
            self.ISP[ISP] += 1

        if country not in self.country.keys():
            self.country[country] = 1
        
        else:
            self.country[country] += 1

    def pwd_change(self, pwd, new_pwd):
        self.old_pwd.append(pwd)
        self.pwd = new_pwd
        self.dur.append(datetime.now() - self.pwd_set_time)
        self.pwd_set_time = datetime.now()

    def getUsrname(self):
        return self.usrname

    def getPwd(self):
        return self.curr_pwd

class login_attempt_log(object):
    def __init__(self, origin, ISP, country, usrname, pwd, outcome, time):
        self.origin = origin
        self.time = time
        self.usrname = usrname
        self.pwd = pwd
        self.outcome = outcome
        self.ISP = ISP
        self.country = country

class failed_attempt_log(login_attempt_log):
    def __init__(self, origin, ISP, country, usrname, pwd, outcome, time):
        super().__init__(origin, ISP, country, usrname, pwd, outcome, time)
        self.prev_time = self.time
        self.count = 1
        self.freq = [0]
        self.attempted_pwd = [pwd]
        self.tz = timezone(self.time.time().hour)

    def update(self, origin, ISP, country, pwd, time):
        self.count += 1
        self.attempted_pwd.append(pwd)
        self.pwd = pwd
        self.time = time
        self.origin = origin
        self.ISP = ISP
        self.country = country
        time_diff = (self.time - self.prev_time).total_seconds() # seconds
        self.freq.append(1/time_diff)
        self.prev_time = self.time
        self.tz = timezone(self.time.time().hour)

    # Calculate deviance on user's origin
    def origin_deviance(self, usr):
        IPs = usr.origin
        seen_ISPs = usr.ISP
        total_ISPs = len(seen_ISPs.keys())

        IPs_from_ISP = 0
        for k in IPs.keys():
            if IPs[k][0] == self.ISP:
                IPs_from_ISP += 1

        seen_countries = usr.country
        total_countries = len(seen_countries.keys())

        IPs_from_country = 0
        for k in IPs.keys():
            if IPs[k][1] == self.country:
                IPs_from_country += 1

        dev = 0

        if self.ISP in seen_ISPs.keys():
            # deviance = Prob(unseen IP)
            dev = (1 / IPs_from_ISP) * (usr.ISP[self.ISP] / total_ISPs)
            return dev

        if self.country in seen_countries.keys():
            # deviance = Prob(unseen IP)
            dev = (1 / IPs_from_country) * (usr.country[self.country] / total_countries)
            return dev

    # Uncertainty on users' attempt timing
    def uncertainty(self, usr):
        # Calculate Shannon's Entropy
        tz = self.tz
        Px = usr.tz_login[tz][0] / (usr.tz_login[tz][0] + usr.tz_login[tz][1])
        Hx = entropy([Px, 1 - Px], base = 2)

        # Calculate perceived threat
        n_e = Hx / (usr.tz_login[tz][0] + usr.tz_login[tz][1]) # normalized entropy n_e
        alpha = 0.3 # reference point
        r_e = 0.5 # exponent for right side of ref. point
        l_e = 1.3 # exponent for left side of ref. point

        if n_e >= alpha:
            threat = n_e ** r_e
        
        else:
            threat = n_e ** l_e

        return threat
    
    def contextual_threat(self, usr):
        C = (1 - self.origin_deviance(usr)) * self.uncertainty(usr)
        return C

    # Calculate deviance on users' password
    def pwd_deviance(self, usr):
        D1 = 0.7
        D2 = 0.5
        D3 = 0.3

        dev = 0

        if self.pwd in usr.old_pwd:
            turn = usr.old_pwd.index(self.pwd) + 1
            dur = usr.dur[turn - 1]
            dev = D2 * exp(-dur / turn)

        elif self.pwd in weak_pwd:
            w = weak_pwd[self.pwd]
            dev = D1 * exp(-self.count * w)

        else:
            lev_dist = enchant.utils.levenshtein(usr.curr_pwd, self.pwd)
            dev = D3 * exp(-1 / lev_dist)

        return dev

    def freq_threat(self):
        A = 0
        K = 0.35
        C = 1

        freq = self.freq[-1]

        f_t = A + ((K - A) / pow(C,(1/freq)))

        return f_t

    def behavorial_threat(self, usr):
        B = self.pwd_deviance(usr) * self.freq_threat()

        return B

    def risk(self, usr):
        alpha = 0.6
        mu = 0.4

        r = alpha * self.contextual_threat(usr) + mu * self.behavorial_threat(usr)

        return r

    def risk_capacity(self, usr):
        C1 = 0.1
        C2 = 0.3
        w = 0.1

        if self.pwd == usr.curr_pwd:
            r_c = 1 - C1 * exp(self.count * w)

        else:
            r_c = C2 * strength_pwd(usr.curr_pwd)

        return r_c

    def block(self,usr):

        r_p = self.risk(usr)
        r_c = self.risk_capacity(usr)

        if r_p > r_c:
            usr.blocked = True

weak_passwords = pd.read_csv(r'C:\Users\Bilas\vscode\Projects\PGA\weak_pwds.txt', header = None)

weak_pwd = {}

for pwd in weak_passwords.iloc[:][0]:
    weight = 0.1
    weak_pwd[pwd] = weight

filename = r'C:\Users\Bilas\vscode\Projects\PGA\users.csv'
usr_df = pd.read_csv(filename)
user_list = list(usr_df['Username'])
usr_df['old_pwd'] = usr_df['old_pwd'].apply(eval)
usr_df['dur'] = usr_df['dur'].apply(eval)
usr_dict = {}

for i in range(len(usr_df)):
    usr_dict[user_list[i]] = user(user_list[i], usr_df.loc[i, 'Password'], usr_df.loc[i, 'old_pwd'], usr_df.loc[i, 'dur'])

filename = r'C:\Users\Bilas\vscode\Projects\PGA\login_data.csv'
login_df = pd.read_csv(filename)
login_df['time'] = pd.to_datetime(login_df['time'])

login_dict = {}
failed_logs = {'Bilas' : None,
                'Anand' : None,
                'John' : None,
                'steve' : None,
                'Jack' : None}

for i in range(100):
    login_dict[i] = login_attempt_log(login_df.loc[i, 'origin'], login_df.loc[i, 'ISP'], login_df.loc[i, 'country'],
                            login_df.loc[i, 'usr'], login_df.loc[i, 'pwd'], login_df.loc[i, 'outcome'], login_df.loc[i, 'time'])

    if (login_df.loc[i, 'outcome'] == 0):
        if(failed_logs[login_df.loc[i, 'usr']] == None):
            failed_logs[login_df.loc[i, 'usr']] = failed_attempt_log(login_df.loc[i, 'origin'], login_df.loc[i, 'ISP'],
                                                    login_df.loc[i, 'country'], login_df.loc[i, 'usr'], login_df.loc[i, 'pwd'], login_df.loc[i, 'outcome'], login_df.loc[i, 'time'])

        else:
            failed_logs[login_df.loc[i, 'usr']].update(login_df.loc[i, 'origin'], login_df.loc[i, 'ISP'], login_df.loc[i, 'country'],
                                                        login_df.loc[i, 'pwd'], login_df.loc[i, 'time'])

        t = login_df.loc[i, 'time'].time()
        tz = timezone(t.hour)
        usr_dict[login_df.loc[i, 'usr']].tz_login[tz][1] += 1

    else:
        usr_dict[login_df.loc[i, 'usr']].login(login_df.loc[i, 'origin'], login_df.loc[i, 'ISP'], login_df.loc[i, 'country'],
                                                login_df.loc[i, 'time'])

filename = r'C:\Users\Bilas\vscode\Projects\PGA\test_data.csv'
test_df = pd.read_csv(filename)
test_df['datetime'] = pd.to_datetime(test_df['datetime'])

for i in range(len(test_df)):
    print('User: ', test_df.loc[i, 'usr'])
    attempt(test_df.loc[i, 'usr'], test_df.loc[i, 'origin'], test_df.loc[i, 'ISP'],
            test_df.loc[i, 'country'], test_df.loc[i, 'pwd'], test_df.loc[i, 'datetime'])
