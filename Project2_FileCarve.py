#Needed imports to properly create code to perform desired functions and created desired output
#Regular Expression import to help searching for file header and footers
import re
#Hashlib was utilized to convert the file name to sha256
import hashlib
#Used to help convert from hex to ascii
import binascii
#Struct import used to handle binary format of file date when carving
import struct
#Used to take in disk drive parameter when calling from console
import sys


def file_find(disk_drive_in):
    #PLaces all of the file signatures in one location to be searched through
    #The first element in the list of lists is the file extension followed by the header, and finally the footer
    #If the file extension does not have a footer, None is inserted to signify this
    #Includes any possible combination of headers and footers to ensure all file types have been accurately searched
    file_info = [
        ["MPG", b'\x00\x00\x01\xB3.\x00', b'\x00\x00\x00\x01\xB7'],
        ["MPG", b'\x00\x00\x01\xBA.\x00', b'\x00\x00\x00\x01\xB9'],
        ["GIF", b'\x47\x49\x46\x38\x37\x61', b'\x00\x00\x3B'],
        ["GIF", b'\x47\x49\x46\x38\x39\x61', b'\x00\x00\x3B'],
        ["PNG", b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A', b'\x49\x45\x4E\x44\xAE\x42\x60\x82'],
        ["JPG", b'\xFF\xD8\xFF\xE0', b'\xFF\xD9'],
        ["JPG", b'\xFF\xD8\xFF\xE1', b'\xFF\xD9'],
        ["JPG", b'\xFF\xD8\xFF\xE2', b'\xFF\xD9'],
        ["JPG", b'\xFF\xD8\xFF\xE8', b'\xFF\xD9'],
        ["JPG", b'\xFF\xD8\xFF\xDB', b'\xFF\xD9'],
        ["DOCX", b'\x50\x4B\x03\x04\x14\x00\x06\x00', b'\x50\x4B\x05\x06'],
        ["PDF", b'\x25\x50\x44\x46', b'\x0A\x25\x25\x45\x4F\x46\x0A'],
        ["PDF", b'\x25\x50\x44\x46', b'\x0D\x0A\x25\x25\x45\x4F\x46\x0D\x0A'],
        ["PDF", b'\x25\x50\x44\x46', b'\x0A\x25\x25\x45\x4F\x46\x0A'],
        ["PDF", b'\x25\x50\x44\x46', b'\x0A\x25\x25\x45\x4F\x46'],
        ["PDF", b'\x25\x50\x44\x46', b'\x0D\x25\x25\x45\x4F\x46\x0D'],
        ["BMP", b'\x42\x4D....\x00\x00\x00\x00', None],
        ["AVI", b'\x52\x49\x46\x46....\x41\x56\x49\x20\x4C\x49\x53\x54', None]
    ]
    #Boolean expressions to help faciliate file carving
    skip_head = False
    skip_foot = False
    skip_pdf = False
    #These arrays keep track of which headers and footers have already been used to prevent duplicates
    used_headers = []
    used_footers = []
    #Used to uniquely identify each file found
    file_num = 1
    #This call opens up the disk drive, grabs its data, assigns it to a variable, and then closes it again. 
    ddPath = disk_drive_in
    diskOpen = open(ddPath, 'rb')
    diskImage = diskOpen.read()
    diskOpen.close()
    #Iterating through each file type and checking for its existence in the disk drive.
    for file_content in file_info:
        #Using regex, it takes the file header and compiles it so it can be searched upon
        file_head = re.compile(file_content[1])
        #Looks in the file database and looks for a matching header to the current file type
        for head_match in file_head.finditer(diskImage):
            #Once located, assign the offset value to a variable
            offset_check = head_match.start()
            skip_head = False
            #Make sure the offset has not been found before. If so, tell program to skip
            if offset_check in used_headers:
                skip_head = True
            #Takes the disk image and substrings it to include only everything after the current offset.
            start_offset = diskImage[offset_check:]
            #PDF Offset is a special case because there could be several offsets and several end of file markers. 
            pdf_offset = 0
            #Assuming it is not a pdf and header has not been previously discovered
            if (skip_head == False):
                if (file_content[0] == "PDF"):
                    for new_match in file_head.finditer(diskImage[offset_check+1:]):
                        pdf_offset = new_match.start() + offset_check
                        break 
                #If footer input is none we know the file signature contains the file size and no need for footer.
                #Must grab the size dependent on which file extension
                if (file_content[2] is None):
                    #BMP header is two bytes before size bytes
                    if (file_content[0] == "BMP"):
                        head_size = 2
                    #AVI header is four bytes before size bytes
                    elif (file_content[0] == "AVI"):
                        head_size = 4
                    #Adjust file start to get bytes that contain the size info of the file
                    file_start = offset_check + head_size
                    #Must grab bytes and convert into decimal/long value. Must remember size is in little endian order to the byte order must be reversed prior to conversion.
                    #Puts file into a string. Converts to hex and then converts hex type to string and concatenates. 
                    file_size = str(hex(diskImage[file_start])[2:].zfill(2)) + str(hex(diskImage[file_start+1])[2:].zfill(2)) + str(hex(diskImage[file_start+2])[2:].zfill(2)) + str(hex(diskImage[file_start+3])[2:].zfill(2))
                    binary_size = binascii.unhexlify(file_size)
                    #The <l flag unpacks the binary and converts it back to its original representation
                    long_size = struct.unpack('<l', binary_size)
                    #Update the ending offset based on the file size in bytes
                    end_found = offset_check + long_size[0]
                    if (file_content[0] == "AVI"):
                        #Need to account for additional bytes for header and file size
                        end_found += 8
                #If file footer data is not equal to None we assume that the file extension we are currently on has a footer to be found
                else:
                    #Compile the footer using regex so that it can be searched for
                    file_foot = re.compile(file_content[2])
                    #Start searching for footer at the header of the currently found file
                    for foot_match in file_foot.finditer(start_offset):
                        #Assign the offset for the end of the file
                        end_found = foot_match.end()
                        #Update the end offset by adding the already traversed bytes
                        end_found += offset_check
                        #Variables created and updated to account for pdf footer searching
                        skip_pdf = False
                        next_end = 0
                        #If it is a docx the footer needs to account for 18 additional bytes according to notes and website
                        if (file_content[0] == "DOCX"):
                            end_found += 18
                            break
                        #Checking to see if file extension is pdf which requires a special case
                        elif(file_content[0] == "PDF"):
                            #Looking for another end of file footer in case the current footer is not the end of file
                            for match_check in file_foot.finditer(diskImage[end_found:]):
                                next_end = match_check.start() + end_found
                                break
                            #If the next value is not 0 there must be another end of file marker
                            if (pdf_offset != 0):
                                #Check to make sure the offset is valid. If the current end of file is higher than the one found then we cannot use it.
                                #Because of this the skip_pdf value is set to true to signify we can skip over this found footer match. 
                                if (end_found > pdf_offset):
                                    skip_pdf = True
                                    break
                                #Make sure that the currently found footer is not past the start of another pdf header.
                                elif (next_end != 0):
                                    #If it is greater, it is safe to assume we can break out of this for loop and the end of file has been found. 
                                    if (next_end > pdf_offset):
                                        break
                        #If it is any other file type, we can break out of this loop
                        else:
                            break
                #Reset footer boolean
                skip_foot = False
                #If the footer has already been found, set boolean expression to true so the current footer can be skipped
                if end_found in used_footers:
                    skip_foot = True
                #If none of the booleans are triggered to true it is safe to assume we have found the proper offsets and can begin carving file
                if not (skip_foot or skip_head or skip_pdf):
                    #Go ahead and add respective values to list so that they cannot be searched for again. 
                    used_headers.append(offset_check)
                    used_footers.append(end_found)
                    #Carve the file data and assign it to a variable
                    file_found = diskImage[offset_check:end_found]
                    #Create unique file name
                    file_name = "File" + str(file_num) + "." + file_content[0]
                    #Open up a file to be written too 
                    file_write = open(file_name, "wb")
                    #Take the data carved and write it to the newly created file
                    file_write.write(file_found)
                    #Close the writer
                    file_write.close()
                    #This is used to create a sha256 hash of the file name. 
                    with open(file_name, "rb") as hashfile:
                        data = hashfile.read(65536)
                        hasher = hashlib.sha256(data)
                        while data:
                            data = hashfile.read(65536)
                            hasher.update(data)
                    #Assigns the value of the hash to this variable
                    name_hash = hasher.hexdigest()
                    #Increase file number so a new file can be written for the next file extension found
                    file_num += 1
                    #Print out desired contents to the console for inspection
                    print("\nFile Name: " + file_name)
                    print("Starting Offset: " + hex(offset_check))
                    print("End Offset: " + hex(end_found))
                    print("SHA-256 Hash: " + name_hash)


file_find(sys.argv[1])


            


