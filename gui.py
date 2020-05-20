from tkinter import *
import tkinter.messagebox as tkMessageBox
import trainer as tr
import webbrowser
import pandas
import main

root = Tk()
root.title("Malicious Url Detector")
img = PhotoImage(width=300,height=300)
data = ("{red red red red blue blue blue blue}")
root.attributes('-alpha',0.9)
root.iconbitmap(r'malware.ico')
#root.configure(background='thistle')
#root.geometry("800x100")
frame = Frame(root)
frame.pack()
bottomframe = Frame(root)
bottomframe.pack(side=BOTTOM)

L1 = Label(frame, text="Enter the URL: ")
L1.pack(side=LEFT)
E1 = Entry(frame, bd=5, width=150)
E1.pack(side=RIGHT)


def submitCallBack():
    url = E1.get()
    main.process_test_url(url, 'test_features.csv')
    return_ans = tr.gui_caller('url_features.csv', 'test_features.csv')
    a = str(return_ans).split()
    print("-----")
    print("return_ans:",return_ans)
    print("-----")
    if int(a[1]) == 0:
        tkMessageBox.showinfo("URL Checker Result", "The URL " + url + " is Safe to Visit")
        new=1
        answer = tkMessageBox.askquestion("Redirect","Do you want to visit the url?")
        if answer == 'yes':
                #webbrowser.open(url=E1.get(), new=1)
                chrome_path = 'C:/Program Files (x86)/Google/Chrome/Application/chrome.exe %s'
                webbrowser.get(chrome_path).open(url=E1.get(),new=1)
    elif int(a[1]) == 1:
        tkMessageBox.showinfo("URL Checker Result", "The URL " + url + " is Malicious")
        answer_2 = tkMessageBox.askquestion("Redirect", "The url MALICIOUS, Do you still want to visit the url?")
        if answer_2=='yes':
            webbrowser.open(url=E1.get(),new=1)
    else:
        tkMessageBox.showinfo("URL Checker Result", "The URL " + url + " is Malware")
        tkMessageBox.showwarning("Warning","Cant Redirect, url contains a malware")

def about():
    tkMessageBox.showinfo("About","Authors: vijay maripi")


B2 = Button(root, text="About", command=about)
B1 = Button(bottomframe, text="Submit", command=submitCallBack)
B2.pack(side=RIGHT, padx=5, pady=5)
B1.pack(side=RIGHT, padx=5,pady=5)
root.mainloop()




