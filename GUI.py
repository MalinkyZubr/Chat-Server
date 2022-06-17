import tkinter as tk
from tkinter import ttk
from ttkthemes import ThemedTk
import time

try: 
    from ctypes import windll
    windll.shcore.SetProcessDpiAwareness(1)
except:
    pass

class GUI:
    def __init__(self):
        ###Boilerplate###
        self.connections = None
        self.messages = None
        self.root = ThemedTk(theme="breeze")
        self.root.geometry("600x600")
        self.root.resizable(True,True)
        self.root.title("Message GUI")
        self.style = ttk.Style()
        self.style.theme_use("keramik")
        ###Frame Instanciation###
        self.left_frame = ttk.Frame(self.root)
        self.chat_frame = ttk.Frame(self.root,width=500,height=300)
        self.connections_frame = ttk.Frame(self.left_frame,width=100,height=300)
        #self.message_frame = ttk.Frame(self.root,width=400,height=10)
        self.commands_frame = ttk.Frame(self.left_frame,width=200,height=200)
        self.logging_frame = ttk.Frame(self.left_frame,width=500,height=200)
        ###Frame Gridding###
        self.left_frame.grid(row=0,column=0,sticky="wns")
        self.chat_frame.grid(row=0,column=1,sticky="nsew",padx=10,pady=10)
        self.connections_frame.grid(row=0,column=0,sticky="nwe",padx=10,pady=10)
        self.commands_frame.grid(row=1,column=0,sticky="nwe",padx=10,pady=10)
        self.logging_frame.grid(row=2,column=0,sticky="nwe",padx=10,pady=10)
        ###Root Configuration###
        self.root.grid_columnconfigure(1,weight=1)
        self.root.grid_columnconfigure(0,weight=1)
        #self.root.grid_rowconfigure(2,weight=3)
        ###Grid Configuration###
        self.connections_frame.grid_columnconfigure(1,weight=1)
        self.chat_frame.grid_columnconfigure(0,weight=1)
        self.chat_frame.grid_rowconfigure(1,weight=1)
        self.logging_frame.grid_columnconfigure(0,weight=1)
        self.commands_frame.grid_columnconfigure(0,weight=0)
        self.commands_frame.grid_columnconfigure(1,weight=1)
        #self.logging_frame.columnconfigure(1,weight=1)
        #self.message_frame.columnconfigure(0,weight=1)
        #self.commands_frame.
        #self.logging_frame.
        #self.files_frame.

    ###Chat Widget Creation###
    def chat_box_widget(self):
        chat_box = tk.Text(
            self.chat_frame,
            fg="black",
            bg="white",
            padx=10,
            pady=10,
            insertontime=0,
        )
        chat_scroll = ttk.Scrollbar(
            self.chat_frame,
            orient="vertical",
            command=chat_box.yview,
        )
        send_button = ttk.Button(
            self.chat_frame,
            text="SEND",
        )
        message_field = ttk.Entry(
            self.chat_frame,
        )
        chat_label = ttk.Label(
            self.chat_frame,
            text="MESSAGES:"
        )
        chat_box["yscrollcommand"] = chat_scroll.set
        ###Chat Widget Commands###
        chat_box.bind("<Key>", lambda e: "break") #read only but programically changeable
        ###Widget Gridding###
        chat_label.grid(row=0,column=0,sticky="ensw")
        chat_box.grid(row=1,columnspan=2,sticky="ensw")
        chat_scroll.grid(row=1,column=2,sticky="ns")
        message_field.grid(row=2,column=0,padx=3,pady=3,sticky="n")
        send_button.grid(row=2,column=1,columnspan=2,sticky="n")

    ###Connections Widget Creation###
    def connections_widget(self):
        connections_box = tk.Text(
            self.connections_frame,
            fg="black",
            bg="white",
            padx=10,
            pady=10,
            insertontime=0,
            width=35,
        )
        connections_scroll = ttk.Scrollbar(
            self.connections_frame,
            orient="vertical",
            command=connections_box.yview
        )
        connections_label = ttk.Label(
            self.connections_frame,
            text="ONLINE:"
        )
        search_entry = ttk.Entry(
            self.connections_frame
        )
        search_button = ttk.Button(
            self.connections_frame,
            text="SEARCH"
        )
        connections_box["yscrollcommand"] = connections_scroll.set
        ###Connections Widget Commands###
        connections_box.bind("<Key>", lambda e: "break") 
        ###Widget Gridding###
        connections_label.grid(row=0,columnspan=2,sticky="wns")
        connections_scroll.grid(row=1,column=0,sticky="ns")
        connections_box.grid(row=1,column=1,columnspan=2,sticky="wns")
        search_entry.grid(row=2,column=0,columnspan=2,sticky="wns")
        search_button.grid(row=2,column=2,sticky="wns")
    
    ###Logging Widget Creation###
    def logging_widget(self):
        logging_box = tk.Text(
            self.logging_frame,
            fg="black",
            bg="white",
            padx=10,
            pady=10,
            #relief="ridge",
            insertontime=0,
            width=35
        )
        log_scroll = ttk.Scrollbar(
            self.logging_frame,
            orient="vertical",
            command=logging_box.yview,
        )
        logging_label = ttk.Label(
            self.logging_frame,
            text="SYSTEM LOGS:"
        )
        logging_box["yscrollcommand"] = log_scroll.set
        ###Chat Widget Commands###
        logging_box.bind("<Key>", lambda e: "break") #read only but programically changeable
        ###Widget Gridding###
        logging_label.grid(row=0,column=0,sticky="wns")
        logging_box.grid(row=1,column=0,sticky="wns")
        log_scroll.grid(row=1,column=1,sticky="ns")

    ###Commands Widget Creation###
    def commands_widget(self):
        command_label = ttk.Label(
            self.commands_frame,
            text="COMMANDS: "
        )
        command_list = ttk.Combobox(
            self.commands_frame
        )
        entry_label = ttk.Label(
            self.commands_frame,
            text="ENTER ARGS"
        )
        entry_field = ttk.Entry(
            self.commands_frame
        )
        command_button = ttk.Button(
            self.commands_frame,
            text="RUN"
        )
        ###Chat Widget Commands###
        command_list['values'] = ('placeholder1','placeholder2','placeholder3')
        ###Widget Gridding###
        command_label.grid(row=0,column=0,sticky="wns")
        command_list.grid(row=0,column=1,columnspan=2,sticky="wns")
        entry_label.grid(row=1,column=0,sticky="wns")
        entry_field.grid(row=1,column=1,sticky="wns")
        command_button.grid(row=1,column=2,sticky="ew")

    def Main(self):
        self.chat_box_widget()
        self.connections_widget()
        self.logging_widget()
        self.commands_widget()
        self.root.mainloop()

if __name__ == "__main__":
    gui = GUI()
    gui.Main()



