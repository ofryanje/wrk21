/*++

Copyright (c) Microsoft Corporation. All rights reserved. 

You may only use this code if you agree to the terms of the Windows Research Kernel Source Code License agreement (see License.txt).
If you do not agree to the terms, do not use the code.


Module Name:

    create.c

Abstract

    This module contains the code to implement the NtCreateFile,
    the NtCreateNamedPipeFile and the NtCreateMailslotFile system
    services.

--*/

#include "iomgr.h"

#pragma alloc_text(PAGE, NtCreateFile)
#pragma alloc_text(PAGE, NtCreateNamedPipeFile)
#pragma alloc_text(PAGE, NtCreateMailslotFile)

NTSTATUS
NtCreateFile (
    __out PHANDLE FileHandle,
    __in ACCESS_MASK DesiredAccess,
    __in POBJECT_ATTRIBUTES ObjectAttributes,
    __out PIO_STATUS_BLOCK IoStatusBlock,
    __in_opt PLARGE_INTEGER AllocationSize,
    __in ULONG FileAttributes,
    __in ULONG ShareAccess,
    __in ULONG CreateDisposition,
    __in ULONG CreateOptions,
    __in_bcount_opt(EaLength) PVOID EaBuffer,
    __in ULONG EaLength
    )

/*++

Routine Description:

    This service opens or creates a file, or opens a device.  It is used to
    establish a file handle to the open device/file that can then be used
    in subsequent operations to perform I/O operations on.  For purposes of
    readability, files and devices are treated as "files" throughout the
    majority of this module and the system service portion of the I/O system.
    The only time a distinction is made is when it is important to determine
    which is really being accessed.  Then a distinction is also made in the
    comments.

Arguments:

    FileHandle - A pointer to a variable to receive the handle to the open file.

    DesiredAccess - Supplies the types of access that the caller would like to
        the file.

    ObjectAttributes - Supplies the attributes to be used for file object (name,
        SECURITY_DESCRIPTOR, etc.)

    IoStatusBlock - Specifies the address of the caller's I/O status block.

    AllocationSize - Initial size that should be allocated to the file.  This
        parameter only has an affect if the file is created.  Further, if
        not specified, then it is taken to mean zero.

    FileAttributes - Specifies the attributes that should be set on the file,
        if it is created.

    ShareAccess - Supplies the types of share access that the caller would like
        to the file.

    CreateDisposition - Supplies the method for handling the create/open.

    CreateOptions - Caller options for how to perform the create/open.

    EaBuffer - Optionally specifies a set of EAs to be applied to the file if
        it is created.

    EaLength - Supplies the length of the EaBuffer.

Return Value:

    The function value is the final status of the create/open operation.

--*/

{
    PUNICODE_STRING name;

    //variables to hold the response from ntopenfile
    NTSTATUS res;
    PHANDLE handle;
    PIO_STATUS_BLOCK io_status;

    //vars for filtering name length
    int name_length = ObjectAttributes->ObjectName->Length / 2;
    WCHAR* ext[3];

    //vars for making the rename request
    PFILE_RENAME_INFORMATION rename_info;
    unsigned long int rename_info_size = (sizeof(FILE_RENAME_INFORMATION) + 22);
    UNICODE_STRING new_name;
    const wchar_t new_buffer[] = L"backup.txt"; //we gotta define it up here?

    PAGED_CODE();

    //print file name, access requested

    if ((ObjectAttributes != NULL) && (ObjectAttributes->ObjectName != NULL))
    {
        name = ObjectAttributes->ObjectName;

        if (DesiredAccess & GENERIC_READ)
        {
            if (DesiredAccess & GENERIC_WRITE)
            {

                DbgPrint("[CREATEFILE] READ & WRITE %wZ\n", name);

            }
            else
            {
                DbgPrint("[CREATEFILE] ONLY READ %wZ\n", name);
            }
        }
        else
        {
            if (DesiredAccess & GENERIC_WRITE)
            {
                DbgPrint("[CREATEFILE] ONLY WRITE %wZ\n", name);

                if (name->Length > 6)
                {

                    ext[0] = (WCHAR*)name->Buffer[name_length - 1];
                    ext[1] = (WCHAR*)name->Buffer[name_length - 2];
                    ext[2] = (WCHAR*)name->Buffer[name_length - 3];

                    if (ext[0] == (WCHAR*)L't' && ext[1] == (WCHAR*)L'x' && ext[2] == (WCHAR*)L't')
                    {
                        //we know this is a txt file, so we can attempt a rename
                        //NtOpenFile()

                        io_status = (PIO_STATUS_BLOCK)ExAllocatePoolWithTag(PagedPool, sizeof(IO_STATUS_BLOCK), (ULONG)'open');
                        handle = (PHANDLE)ExAllocatePoolWithTag(PagedPool, sizeof(HANDLE), (ULONG)'file');

                        //attempt to get a handle to the file
                        if ((io_status != NULL) && (handle != NULL))
                        {
                            res = ZwOpenFile(handle, 1114240, ObjectAttributes, io_status, 7, 2113568);
                            if (NT_SUCCESS(res))
                            {
                                DbgPrint("[DEBUG] NTOPENFILE SUCCESS\n");

                                //
                                // setup a new name to replace the old one
                                //

                                new_name.Buffer = (PWSTR) &new_buffer; //converting wchar_t[] pointer -> PWSTR
                                new_name.Length = 22; //(10 + a null terminator) * 2
                                new_name.MaximumLength = 22; //same as above, the value won't change

                                //debug (remove later)
                                DbgPrint("[DEBUG] new_buffer: %ls \n", new_buffer);
                                DbgPrint("[DEBUG] new_name: %wZ \n", &new_name);

                                //
                                // initialize a rename info object
                                //

                                rename_info = (PFILE_RENAME_INFORMATION)ExAllocatePoolWithTag(PagedPool, rename_info_size, (ULONG)'renm');
                                rename_info->RootDirectory = ObjectAttributes->RootDirectory; //but will it work?
                                rename_info->ReplaceIfExists = FALSE; //guessing that this should be false
                                rename_info->FileNameLength = (ULONG)new_name.Length;
                                //replace the given string with the one we just created
                                RtlCopyMemory(rename_info->FileName, new_name.Buffer, new_name.Length);

                                //debug (remove later)
                                //i am passing a string value to this function
                                DbgPrint("[DEBUG] NEW FILE NAME: %ls \n", rename_info->FileName);

                                //
                                //attempt to call SetInformationFile
                                //

                                // size needs to be a ULONG (i think)
                                // fml i was using "filenameinformation" this whole fucking time AAAAAAAAAAAAAAAAAAAAAAAAAAAAA
                                res = ZwSetInformationFile(*handle, io_status, (PVOID)rename_info, (ULONG)rename_info_size, FileRenameInformation);


                                //check if the call succeeded...
                                if (NT_SUCCESS(res))
                                {
                                    DbgPrint("[DEBUG] SETINFORMATIONFILE SUCCESS!\n");
                                }
                                else
                                {
                                    DbgPrint("[DEBUG] SETINFORMATIONFILE FAILED! ERROR: %lx\n", res);
                                }

                                //close the handle when we're done using it
                                NtClose(*handle);
                            }
                            else
                            {
                                DbgPrint("[DEBUG] NTOPENFILE FAILED, ERROR: %lX\n", res);
                            }
                        }
                        else
                        {
                            DbgPrint("[DEBUG] MEMORY ALLOCATION FAILED!\n");
                        }
                    }
                }
            }
        }
    }

    return IoCreateFile( FileHandle,
                         DesiredAccess,
                         ObjectAttributes,
                         IoStatusBlock,
                         AllocationSize,
                         FileAttributes,
                         ShareAccess,
                         CreateDisposition,
                         CreateOptions,
                         EaBuffer,
                         EaLength,
                         CreateFileTypeNone,
                         (PVOID)NULL,
                         0 );
}

NTSTATUS
NtCreateNamedPipeFile (
     __out PHANDLE FileHandle,
     __in ULONG DesiredAccess,
     __in POBJECT_ATTRIBUTES ObjectAttributes,
     __out PIO_STATUS_BLOCK IoStatusBlock,
     __in ULONG ShareAccess,
     __in ULONG CreateDisposition,
     __in ULONG CreateOptions,
     __in ULONG NamedPipeType,
     __in ULONG ReadMode,
     __in ULONG CompletionMode,
     __in ULONG MaximumInstances,
     __in ULONG InboundQuota,
     __in ULONG OutboundQuota,
     __in_opt PLARGE_INTEGER DefaultTimeout
     )

/*++

Routine Description:

    Creates and opens the server end handle of the first instance of a
    specific named pipe or another instance of an existing named pipe.

Arguments:

    FileHandle - Supplies a handle to the file on which the service is being
        performed.

    DesiredAccess - Supplies the types of access that the caller would like to
        the file.

    ObjectAttributes - Supplies the attributes to be used for file object
        (name, SECURITY_DESCRIPTOR, etc.)

    IoStatusBlock - Address of the caller's I/O status block.

    ShareAccess - Supplies the types of share access that the caller would
        like to the file.

    CreateDisposition - Supplies the method for handling the create/open.

    CreateOptions - Caller options for how to perform the create/open.

    NamedPipeType - Type of named pipe to create (Bitstream or message).

    ReadMode - Mode in which to read the pipe (Bitstream or message).

    CompletionMode - Specifies how the operation is to be completed.

    MaximumInstances - Maximum number of simultaneous instances of the named
        pipe.

    InboundQuota - Specifies the pool quota that is reserved for writes to the
        inbound side of the named pipe.

    OutboundQuota - Specifies the pool quota that is reserved for writes to
        the inbound side of the named pipe.

    DefaultTimeout - Optional pointer to a timeout value that is used if a
        timeout value is not specified when waiting for an instance of a named
        pipe.

Return Value:

    The function value is the final status of the create/open operation.

--*/

{
    NAMED_PIPE_CREATE_PARAMETERS namedPipeCreateParameters;

    PAGED_CODE();

    //
    // Check whether or not the DefaultTimeout parameter was specified.  If
    // so, then capture it in the named pipe create parameter structure.
    //

    if (ARGUMENT_PRESENT( DefaultTimeout )) {

        //
        // Indicate that a default timeout period was specified.
        //

        namedPipeCreateParameters.TimeoutSpecified = TRUE;

        //
        // A default timeout parameter was specified.  Check to see whether
        // the caller's mode is kernel and if not capture the parameter inside
        // of a try...except clause.
        //

        if (KeGetPreviousMode() != KernelMode) {
            try {
                ProbeForReadSmallStructure ( DefaultTimeout,
                                             sizeof( LARGE_INTEGER ),
                                             sizeof( ULONG ) );
                namedPipeCreateParameters.DefaultTimeout = *DefaultTimeout;
            } except(EXCEPTION_EXECUTE_HANDLER) {

                //
                // Something went awry attempting to access the parameter.
                // Get the reason for the error and return it as the status
                // value from this service.
                //

                return GetExceptionCode();
            }
        } else {

            //
            // The caller's mode was kernel so simply store the parameter.
            //

            namedPipeCreateParameters.DefaultTimeout = *DefaultTimeout;
        }
    } else {

        //
        // Indicate that no default timeout period was specified.
        //

        namedPipeCreateParameters.TimeoutSpecified = FALSE;
    }

    //
    // Store the remainder of the named pipe-specific parameters in the
    // structure for use in the call to the common create file routine.
    //

    namedPipeCreateParameters.NamedPipeType = NamedPipeType;
    namedPipeCreateParameters.ReadMode = ReadMode;
    namedPipeCreateParameters.CompletionMode = CompletionMode;
    namedPipeCreateParameters.MaximumInstances = MaximumInstances;
    namedPipeCreateParameters.InboundQuota = InboundQuota;
    namedPipeCreateParameters.OutboundQuota = OutboundQuota;

    //
    // Simply perform the remainder of the service by allowing the common
    // file creation code to do the work.
    //

    return IoCreateFile( FileHandle,
                         DesiredAccess,
                         ObjectAttributes,
                         IoStatusBlock,
                         (PLARGE_INTEGER) NULL,
                         0L,
                         ShareAccess,
                         CreateDisposition,
                         CreateOptions,
                         (PVOID) NULL,
                         0L,
                         CreateFileTypeNamedPipe,
                         &namedPipeCreateParameters,
                         0 );
}

NTSTATUS
NtCreateMailslotFile (
     __out PHANDLE FileHandle,
     __in ULONG DesiredAccess,
     __in POBJECT_ATTRIBUTES ObjectAttributes,
     __out PIO_STATUS_BLOCK IoStatusBlock,
     __in ULONG CreateOptions,
     __in ULONG MailslotQuota,
     __in ULONG MaximumMessageSize,
     __in PLARGE_INTEGER ReadTimeout
     )

/*++

Routine Description:

    Creates and opens the server end handle of a mailslot file.

Arguments:

    FileHandle - Supplies a handle to the file on which the service is being
        performed.

    DesiredAccess - Supplies the types of access that the caller would like to
        the file.

    ObjectAttributes - Supplies the attributes to be used for file object
        (name, SECURITY_DESCRIPTOR, etc.)

    IoStatusBlock - Address of the caller's I/O status block.

    CreateOptions - Caller options for how to perform the create/open.

    MailslotQuota - Specifies the pool quota that is reserved for writes
        to this mailslot.

    MaximumMessageSize - Specifies the size of the largest message that
        can be written to this mailslot.

    ReadTimeout - The timeout period for a read operation.  This must
        be specified as a relative time.

Return Value:

    The function value is the final status of the create operation.

--*/

{
    MAILSLOT_CREATE_PARAMETERS mailslotCreateParameters;

    PAGED_CODE();

    //
    // Check whether or not the DefaultTimeout parameter was specified.  If
    // so, then capture it in the mailslot create parameter structure.
    //

    if (ARGUMENT_PRESENT( ReadTimeout )) {

        //
        // Indicate that a read timeout period was specified.
        //

        mailslotCreateParameters.TimeoutSpecified = TRUE;

        //
        // A read timeout parameter was specified.  Check to see whether
        // the caller's mode is kernel and if not capture the parameter inside
        // of a try...except clause.
        //

        if (KeGetPreviousMode() != KernelMode) {
            try {
                ProbeForReadSmallStructure( ReadTimeout,
                                            sizeof( LARGE_INTEGER ),
                                            sizeof( ULONG ) );
                mailslotCreateParameters.ReadTimeout = *ReadTimeout;
            } except(EXCEPTION_EXECUTE_HANDLER) {

                //
                // Something went awry attempting to access the parameter.
                // Get the reason for the error and return it as the status
                // value from this service.
                //

                return GetExceptionCode();
            }
        } else {

            //
            // The caller's mode was kernel so simply store the parameter.
            //

            mailslotCreateParameters.ReadTimeout = *ReadTimeout;
        }
    } else {

        //
        // Indicate that no default timeout period was specified.
        //

        mailslotCreateParameters.TimeoutSpecified = FALSE;
    }

    //
    // Store the mailslot-specific parameters in the structure for use
    // in the call to the common create file routine.
    //

    mailslotCreateParameters.MailslotQuota = MailslotQuota;
    mailslotCreateParameters.MaximumMessageSize = MaximumMessageSize;

    //
    // Simply perform the remainder of the service by allowing the common
    // file creation code to do the work.
    //

    return IoCreateFile( FileHandle,
                         DesiredAccess,
                         ObjectAttributes,
                         IoStatusBlock,
                         (PLARGE_INTEGER) NULL,
                         0L,
                         FILE_SHARE_READ | FILE_SHARE_WRITE,
                         FILE_CREATE,
                         CreateOptions,
                         (PVOID) NULL,
                         0L,
                         CreateFileTypeMailslot,
                         &mailslotCreateParameters,
                         0 );
}

