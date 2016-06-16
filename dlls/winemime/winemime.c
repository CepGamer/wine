/*
 * Copyright (C) 2016 Sergei Bolotov
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include "config.h"
#include "wine/port.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <errno.h>
#include <stdarg.h>
#ifdef HAVE_FNMATCH_H
#include <fnmatch.h>
#endif

#define COBJMACROS
#define NONAMELESSUNION

#include <windows.h>
#include <shlobj.h>
#include <objidl.h>
#include <shlguid.h>
#include <appmgmt.h>
#include <tlhelp32.h>
#include <intshcut.h>
#include <shlwapi.h>
#include <initguid.h>
#include <wincodec.h>

#include "wine/unicode.h"
#include "wine/debug.h"
#include "wine/library.h"
#include "wine/list.h"
#include "wine/rbtree.h"

WINE_DEFAULT_DEBUG_CHANNEL(winemime);

#include "wine/winemime.h"

typedef struct
{
    BYTE bWidth;
    BYTE bHeight;
    BYTE bColorCount;
    BYTE bReserved;
    WORD wPlanes;
    WORD wBitCount;
    DWORD dwBytesInRes;
    WORD nID;
} GRPICONDIRENTRY;

typedef struct
{
    WORD idReserved;
    WORD idType;
    WORD idCount;
    GRPICONDIRENTRY idEntries[1];
} GRPICONDIR;

typedef struct
{
    BYTE bWidth;
    BYTE bHeight;
    BYTE bColorCount;
    BYTE bReserved;
    WORD wPlanes;
    WORD wBitCount;
    DWORD dwBytesInRes;
    DWORD dwImageOffset;
} ICONDIRENTRY;

typedef struct
{
    WORD idReserved;
    WORD idType;
    WORD idCount;
} ICONDIR;

typedef struct
{
    WORD offset;
    WORD length;
    WORD flags;
    WORD id;
    WORD handle;
    WORD usage;
} NE_NAMEINFO;

typedef struct
{
    WORD  type_id;
    WORD  count;
    DWORD resloader;
} NE_TYPEINFO;

#define NE_RSCTYPE_ICON        0x8003
#define NE_RSCTYPE_GROUP_ICON  0x800e

typedef struct
{
        HRSRC *pResInfo;
        int   nIndex;
} ENUMRESSTRUCT;

struct xdg_mime_type
{
    char *mimeType;
    char *glob;
    char *lower_glob;
    struct list entry;
};

struct rb_string_entry
{
    char *string;
    struct wine_rb_entry entry;
};

DEFINE_GUID(CLSID_WICIcnsEncoder, 0x312fb6f1,0xb767,0x409d,0x8a,0x6d,0x0f,0xc1,0x54,0xd4,0xf0,0x5c);

static char *xdg_config_dir;
static char *xdg_data_dir;
static char *xdg_desktop_dir;


/* Utility routines */
static unsigned short crc16(const char* string)
{
    unsigned short crc = 0;
    int i, j, xor_poly;

    for (i = 0; string[i] != 0; i++)
    {
        char c = string[i];
        for (j = 0; j < 8; c >>= 1, j++)
        {
            xor_poly = (c ^ crc) & 1;
            crc >>= 1;
            if (xor_poly)
                crc ^= 0xa001;
        }
    }
    return crc;
}

static char *strdupA( const char *str )
{
    char *ret;

    if (!str) return NULL;
    if ((ret = HeapAlloc( GetProcessHeap(), 0, strlen(str) + 1 ))) strcpy( ret, str );
    return ret;
}

static char* heap_printf(const char *format, ...)
{
    va_list args;
    int size = 4096;
    char *buffer, *ret;
    int n;

    while (1)
    {
        buffer = HeapAlloc(GetProcessHeap(), 0, size);
        if (buffer == NULL)
            break;
        va_start(args, format);
        n = vsnprintf(buffer, size, format, args);
        va_end(args);
        if (n == -1)
            size *= 2;
        else if (n >= size)
            size = n + 1;
        else
            break;
        HeapFree(GetProcessHeap(), 0, buffer);
    }

    if (!buffer) return NULL;
    ret = HeapReAlloc(GetProcessHeap(), 0, buffer, strlen(buffer) + 1 );
    if (!ret) ret = buffer;
    return ret;
}

static void write_xml_text(FILE *file, const char *text)
{
    int i;
    for (i = 0; text[i]; i++)
    {
        if (text[i] == '&')
            fputs("&amp;", file);
        else if (text[i] == '<')
            fputs("&lt;", file);
        else if (text[i] == '>')
            fputs("&gt;", file);
        else if (text[i] == '\'')
            fputs("&apos;", file);
        else if (text[i] == '"')
            fputs("&quot;", file);
        else
            fputc(text[i], file);
    }
}

static BOOL create_directories(char *directory)
{
    BOOL ret = TRUE;
    int i;

    for (i = 0; directory[i]; i++)
    {
        if (i > 0 && directory[i] == '/')
        {
            directory[i] = 0;
            mkdir(directory, 0777);
            directory[i] = '/';
        }
    }
    if (mkdir(directory, 0777) && errno != EEXIST)
       ret = FALSE;

    return ret;
}

static char* wchars_to_utf8_chars(LPCWSTR string)
{
    char *ret;
    INT size = WideCharToMultiByte(CP_UTF8, 0, string, -1, NULL, 0, NULL, NULL);
    ret = HeapAlloc(GetProcessHeap(), 0, size);
    if (ret)
        WideCharToMultiByte(CP_UTF8, 0, string, -1, ret, size, NULL, NULL);
    return ret;
}

static WCHAR* utf8_chars_to_wchars(LPCSTR string)
{
    WCHAR *ret;
    INT size = MultiByteToWideChar(CP_UTF8, 0, string, -1, NULL, 0);
    ret = HeapAlloc(GetProcessHeap(), 0, size * sizeof(WCHAR));
    if (ret)
        MultiByteToWideChar(CP_UTF8, 0, string, -1, ret, size);
    return ret;
}

/* Icon extraction routines
 *
 * FIXME: should use PrivateExtractIcons and friends
 * FIXME: should not use stdio
 */

static HRESULT convert_to_native_icon(IStream *icoFile, int *indices, int numIndices,
                                      const CLSID *outputFormat, const char *outputFileName, LPCWSTR commentW)
{
    WCHAR *dosOutputFileName = NULL;
    IWICImagingFactory *factory = NULL;
    IWICBitmapDecoder *decoder = NULL;
    IWICBitmapEncoder *encoder = NULL;
    IWICBitmapScaler *scaler = NULL;
    IStream *outputFile = NULL;
    int i;
    HRESULT hr = E_FAIL;

    dosOutputFileName = wine_get_dos_file_name(outputFileName);
    if (dosOutputFileName == NULL)
    {
        WINE_ERR("error converting %s to DOS file name\n", outputFileName);
        goto end;
    }
    hr = CoCreateInstance(&CLSID_WICImagingFactory, NULL, CLSCTX_INPROC_SERVER,
        &IID_IWICImagingFactory, (void**)&factory);
    if (FAILED(hr))
    {
        WINE_ERR("error 0x%08X creating IWICImagingFactory\n", hr);
        goto end;
    }
    hr = IWICImagingFactory_CreateDecoderFromStream(factory, icoFile, NULL,
        WICDecodeMetadataCacheOnDemand, &decoder);
    if (FAILED(hr))
    {
        WINE_ERR("error 0x%08X creating IWICBitmapDecoder\n", hr);
        goto end;
    }
    if (IsEqualCLSID(outputFormat,&CLSID_WICIcnsEncoder))
    {
        hr = IWICImagingFactory_CreateBitmapScaler(factory, &scaler);
        if (FAILED(hr))
        {
            WINE_WARN("error 0x%08X creating IWICBitmapScaler\n", hr);
        }
    }
    hr = CoCreateInstance(outputFormat, NULL, CLSCTX_INPROC_SERVER,
        &IID_IWICBitmapEncoder, (void**)&encoder);
    if (FAILED(hr))
    {
        WINE_ERR("error 0x%08X creating bitmap encoder\n", hr);
        goto end;
    }
    hr = SHCreateStreamOnFileW(dosOutputFileName, STGM_CREATE | STGM_WRITE, &outputFile);
    if (FAILED(hr))
    {
        WINE_ERR("error 0x%08X creating output file %s\n", hr, wine_dbgstr_w(dosOutputFileName));
        goto end;
    }
    hr = IWICBitmapEncoder_Initialize(encoder, outputFile, GENERIC_WRITE);
    if (FAILED(hr))
    {
        WINE_ERR("error 0x%08X initializing encoder\n", hr);
        goto end;
    }

    for (i = 0; i < numIndices; i++)
    {
        IWICBitmapFrameDecode *sourceFrame = NULL;
        IWICBitmapSource *sourceBitmap = NULL;
        IWICBitmapFrameEncode *dstFrame = NULL;
        IPropertyBag2 *options = NULL;
        UINT width, height;

        hr = IWICBitmapDecoder_GetFrame(decoder, indices[i], &sourceFrame);
        if (FAILED(hr))
        {
            WINE_ERR("error 0x%08X getting frame %d\n", hr, indices[i]);
            goto endloop;
        }
        hr = WICConvertBitmapSource(&GUID_WICPixelFormat32bppBGRA, (IWICBitmapSource*)sourceFrame, &sourceBitmap);
        if (FAILED(hr))
        {
            WINE_ERR("error 0x%08X converting bitmap to 32bppBGRA\n", hr);
            goto endloop;
        }
        if ( scaler)
        {
            IWICBitmapSource_GetSize(sourceBitmap, &width, &height);
            if (width == 64) /* Classic Mode */
            {
                hr = IWICBitmapScaler_Initialize( scaler, sourceBitmap, 128, 128,
                                  WICBitmapInterpolationModeNearestNeighbor);
                if (FAILED(hr))
                    WINE_ERR("error 0x%08X scaling bitmap\n", hr);
                else
                {
                    IWICBitmapSource_Release(sourceBitmap);
                    IWICBitmapScaler_QueryInterface(scaler, &IID_IWICBitmapSource, (LPVOID)&sourceBitmap);
                }
            }
        }
        hr = IWICBitmapEncoder_CreateNewFrame(encoder, &dstFrame, &options);
        if (FAILED(hr))
        {
            WINE_ERR("error 0x%08X creating encoder frame\n", hr);
            goto endloop;
        }
        hr = IWICBitmapFrameEncode_Initialize(dstFrame, options);
        if (FAILED(hr))
        {
            WINE_ERR("error 0x%08X initializing encoder frame\n", hr);
            goto endloop;
        }
        hr = IWICBitmapSource_GetSize(sourceBitmap, &width, &height);
        if (FAILED(hr))
        {
            WINE_ERR("error 0x%08X getting source bitmap size\n", hr);
            goto endloop;
        }
        hr = IWICBitmapFrameEncode_SetSize(dstFrame, width, height);
        if (FAILED(hr))
        {
            WINE_ERR("error 0x%08X setting destination bitmap size\n", hr);
            goto endloop;
        }
        hr = IWICBitmapFrameEncode_SetResolution(dstFrame, 96, 96);
        if (FAILED(hr))
        {
            WINE_ERR("error 0x%08X setting destination bitmap resolution\n", hr);
            goto endloop;
        }
        hr = IWICBitmapFrameEncode_WriteSource(dstFrame, sourceBitmap, NULL);
        if (FAILED(hr))
        {
            WINE_ERR("error 0x%08X copying bitmaps\n", hr);
            goto endloop;
        }
        hr = IWICBitmapFrameEncode_Commit(dstFrame);
        if (FAILED(hr))
        {
            WINE_ERR("error 0x%08X committing frame\n", hr);
            goto endloop;
        }
    endloop:
        if (sourceFrame)
            IWICBitmapFrameDecode_Release(sourceFrame);
        if (sourceBitmap)
            IWICBitmapSource_Release(sourceBitmap);
        if (dstFrame)
            IWICBitmapFrameEncode_Release(dstFrame);
        if (options)
            IPropertyBag2_Release(options);
    }

    hr = IWICBitmapEncoder_Commit(encoder);
    if (FAILED(hr))
    {
        WINE_ERR("error 0x%08X committing encoder\n", hr);
        goto end;
    }

end:
    HeapFree(GetProcessHeap(), 0, dosOutputFileName);
    if (factory)
        IWICImagingFactory_Release(factory);
    if (decoder)
        IWICBitmapDecoder_Release(decoder);
    if (scaler)
        IWICBitmapScaler_Release(scaler);
    if (encoder)
        IWICBitmapEncoder_Release(encoder);
    if (outputFile)
        IStream_Release(outputFile);
    return hr;
}

struct IconData16 {
    BYTE *fileBytes;
    DWORD fileSize;
    NE_TYPEINFO *iconResources;
    WORD alignmentShiftCount;
};

static int populate_module16_icons(struct IconData16 *iconData16, GRPICONDIR *grpIconDir, ICONDIRENTRY *iconDirEntries, BYTE *icons, SIZE_T *iconOffset)
{
    int i, j;
    int validEntries = 0;

    for (i = 0; i < grpIconDir->idCount; i++)
    {
        BYTE *iconPtr = (BYTE*)iconData16->iconResources;
        NE_NAMEINFO *matchingIcon = NULL;
        iconPtr += sizeof(NE_TYPEINFO);
        for (j = 0; j < iconData16->iconResources->count; j++)
        {
            NE_NAMEINFO *iconInfo = (NE_NAMEINFO*)iconPtr;
            if ((((BYTE*)iconPtr) + sizeof(NE_NAMEINFO)) > (iconData16->fileBytes + iconData16->fileSize))
            {
                WINE_WARN("file too small for icon NE_NAMEINFO\n");
                break;
            }
            if (iconInfo->id == (0x8000 | grpIconDir->idEntries[i].nID))
            {
                matchingIcon = iconInfo;
                break;
            }
            iconPtr += sizeof(NE_NAMEINFO);
        }

        if (matchingIcon == NULL)
            continue;
        if (((matchingIcon->offset << iconData16->alignmentShiftCount) + grpIconDir->idEntries[i].dwBytesInRes) > iconData16->fileSize)
        {
            WINE_WARN("file too small for icon contents\n");
            break;
        }

        iconDirEntries[validEntries].bWidth = grpIconDir->idEntries[i].bWidth;
        iconDirEntries[validEntries].bHeight = grpIconDir->idEntries[i].bHeight;
        iconDirEntries[validEntries].bColorCount = grpIconDir->idEntries[i].bColorCount;
        iconDirEntries[validEntries].bReserved = grpIconDir->idEntries[i].bReserved;
        iconDirEntries[validEntries].wPlanes = grpIconDir->idEntries[i].wPlanes;
        iconDirEntries[validEntries].wBitCount = grpIconDir->idEntries[i].wBitCount;
        iconDirEntries[validEntries].dwBytesInRes = grpIconDir->idEntries[i].dwBytesInRes;
        iconDirEntries[validEntries].dwImageOffset = *iconOffset;
        validEntries++;
        memcpy(&icons[*iconOffset], &iconData16->fileBytes[matchingIcon->offset << iconData16->alignmentShiftCount], grpIconDir->idEntries[i].dwBytesInRes);
        *iconOffset += grpIconDir->idEntries[i].dwBytesInRes;
    }
    return validEntries;
}

static int populate_module_icons(HMODULE hModule, GRPICONDIR *grpIconDir, ICONDIRENTRY *iconDirEntries, BYTE *icons, SIZE_T *iconOffset)
{
    int i;
    int validEntries = 0;

    for (i = 0; i < grpIconDir->idCount; i++)
    {
        HRSRC hResInfo;
        LPCWSTR lpName = MAKEINTRESOURCEW(grpIconDir->idEntries[i].nID);
        if ((hResInfo = FindResourceW(hModule, lpName, (LPCWSTR)RT_ICON)))
        {
            HGLOBAL hResData;
            if ((hResData = LoadResource(hModule, hResInfo)))
            {
                BITMAPINFO *pIcon;
                DWORD size = min( grpIconDir->idEntries[i].dwBytesInRes, ((IMAGE_RESOURCE_DATA_ENTRY *)hResInfo)->Size );
                if ((pIcon = LockResource(hResData)))
                {
                    iconDirEntries[validEntries].bWidth = grpIconDir->idEntries[i].bWidth;
                    iconDirEntries[validEntries].bHeight = grpIconDir->idEntries[i].bHeight;
                    iconDirEntries[validEntries].bColorCount = grpIconDir->idEntries[i].bColorCount;
                    iconDirEntries[validEntries].bReserved = grpIconDir->idEntries[i].bReserved;
                    iconDirEntries[validEntries].wPlanes = grpIconDir->idEntries[i].wPlanes;
                    iconDirEntries[validEntries].wBitCount = grpIconDir->idEntries[i].wBitCount;
                    iconDirEntries[validEntries].dwBytesInRes = size;
                    iconDirEntries[validEntries].dwImageOffset = *iconOffset;
                    validEntries++;
                    memcpy(&icons[*iconOffset], pIcon, size);
                    *iconOffset += size;
                }
                FreeResource(hResData);
            }
        }
    }
    return validEntries;
}

static IStream *add_module_icons_to_stream(struct IconData16 *iconData16, HMODULE hModule, GRPICONDIR *grpIconDir)
{
    int i;
    SIZE_T iconsSize = 0;
    BYTE *icons = NULL;
    ICONDIRENTRY *iconDirEntries = NULL;
    IStream *stream = NULL;
    HRESULT hr = E_FAIL;
    ULONG bytesWritten;
    ICONDIR iconDir;
    SIZE_T iconOffset;
    int validEntries = 0;
    LARGE_INTEGER zero;

    for (i = 0; i < grpIconDir->idCount; i++)
        iconsSize += grpIconDir->idEntries[i].dwBytesInRes;
    icons = HeapAlloc(GetProcessHeap(), 0, iconsSize);
    if (icons == NULL)
    {
        WINE_ERR("out of memory allocating icon\n");
        goto end;
    }

    iconDirEntries = HeapAlloc(GetProcessHeap(), 0, grpIconDir->idCount*sizeof(ICONDIRENTRY));
    if (iconDirEntries == NULL)
    {
        WINE_ERR("out of memory allocating icon dir entries\n");
        goto end;
    }

    hr = CreateStreamOnHGlobal(NULL, TRUE, &stream);
    if (FAILED(hr))
    {
        WINE_ERR("error creating icon stream\n");
        goto end;
    }

    iconOffset = 0;
    if (iconData16)
        validEntries = populate_module16_icons(iconData16, grpIconDir, iconDirEntries, icons, &iconOffset);
    else if (hModule)
        validEntries = populate_module_icons(hModule, grpIconDir, iconDirEntries, icons, &iconOffset);

    if (validEntries == 0)
    {
        WINE_ERR("no valid icon entries\n");
        goto end;
    }

    iconDir.idReserved = 0;
    iconDir.idType = 1;
    iconDir.idCount = validEntries;
    hr = IStream_Write(stream, &iconDir, sizeof(iconDir), &bytesWritten);
    if (FAILED(hr) || bytesWritten != sizeof(iconDir))
    {
        WINE_ERR("error 0x%08X writing icon stream\n", hr);
        goto end;
    }
    for (i = 0; i < validEntries; i++)
        iconDirEntries[i].dwImageOffset += sizeof(ICONDIR) + validEntries*sizeof(ICONDIRENTRY);
    hr = IStream_Write(stream, iconDirEntries, validEntries*sizeof(ICONDIRENTRY), &bytesWritten);
    if (FAILED(hr) || bytesWritten != validEntries*sizeof(ICONDIRENTRY))
    {
        WINE_ERR("error 0x%08X writing icon dir entries to stream\n", hr);
        goto end;
    }
    hr = IStream_Write(stream, icons, iconOffset, &bytesWritten);
    if (FAILED(hr) || bytesWritten != iconOffset)
    {
        WINE_ERR("error 0x%08X writing icon images to stream\n", hr);
        goto end;
    }
    zero.QuadPart = 0;
    hr = IStream_Seek(stream, zero, STREAM_SEEK_SET, NULL);

end:
    HeapFree(GetProcessHeap(), 0, icons);
    HeapFree(GetProcessHeap(), 0, iconDirEntries);
    if (FAILED(hr) && stream != NULL)
    {
        IStream_Release(stream);
        stream = NULL;
    }
    return stream;
}

static HRESULT open_module16_icon(LPCWSTR szFileName, int nIndex, IStream **ppStream)
{
    HANDLE hFile = INVALID_HANDLE_VALUE;
    HANDLE hFileMapping = NULL;
    DWORD fileSize;
    BYTE *fileBytes = NULL;
    IMAGE_DOS_HEADER *dosHeader;
    IMAGE_OS2_HEADER *neHeader;
    BYTE *rsrcTab;
    NE_TYPEINFO *iconGroupResources;
    NE_TYPEINFO *iconResources;
    NE_NAMEINFO *iconDirPtr;
    GRPICONDIR *iconDir;
    WORD alignmentShiftCount;
    struct IconData16 iconData16;
    HRESULT hr = E_FAIL;

    hFile = CreateFileW(szFileName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
        OPEN_EXISTING, FILE_FLAG_RANDOM_ACCESS, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        WINE_WARN("opening %s failed with error %d\n", wine_dbgstr_w(szFileName), GetLastError());
        goto end;
    }

    hFileMapping = CreateFileMappingW(hFile, NULL, PAGE_READONLY | SEC_COMMIT, 0, 0, NULL);
    if (hFileMapping == NULL)
    {
        WINE_WARN("CreateFileMapping failed, error %d\n", GetLastError());
        goto end;
    }

    fileSize = GetFileSize(hFile, NULL);

    fileBytes = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
    if (fileBytes == NULL)
    {
        WINE_WARN("MapViewOfFile failed, error %d\n", GetLastError());
        goto end;
    }

    dosHeader = (IMAGE_DOS_HEADER*)fileBytes;
    if (sizeof(IMAGE_DOS_HEADER) >= fileSize || dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        WINE_WARN("file too small for MZ header\n");
        goto end;
    }

    neHeader = (IMAGE_OS2_HEADER*)(fileBytes + dosHeader->e_lfanew);
    if ((((BYTE*)neHeader) + sizeof(IMAGE_OS2_HEADER)) > (fileBytes + fileSize) ||
        neHeader->ne_magic != IMAGE_OS2_SIGNATURE)
    {
        WINE_WARN("file too small for NE header\n");
        goto end;
    }

    rsrcTab = ((BYTE*)neHeader) + neHeader->ne_rsrctab;
    if ((rsrcTab + 2) > (fileBytes + fileSize))
    {
        WINE_WARN("file too small for resource table\n");
        goto end;
    }

    alignmentShiftCount = *(WORD*)rsrcTab;
    rsrcTab += 2;
    iconGroupResources = NULL;
    iconResources = NULL;
    for (;;)
    {
        NE_TYPEINFO *neTypeInfo = (NE_TYPEINFO*)rsrcTab;
        if ((rsrcTab + sizeof(NE_TYPEINFO)) > (fileBytes + fileSize))
        {
            WINE_WARN("file too small for resource table\n");
            goto end;
        }
        if (neTypeInfo->type_id == 0)
            break;
        else if (neTypeInfo->type_id == NE_RSCTYPE_GROUP_ICON)
            iconGroupResources = neTypeInfo;
        else if (neTypeInfo->type_id == NE_RSCTYPE_ICON)
            iconResources = neTypeInfo;
        rsrcTab += sizeof(NE_TYPEINFO) + neTypeInfo->count*sizeof(NE_NAMEINFO);
    }
    if (iconGroupResources == NULL)
    {
        WINE_WARN("no group icon resource type found\n");
        goto end;
    }
    if (iconResources == NULL)
    {
        WINE_WARN("no icon resource type found\n");
        goto end;
    }

    if (nIndex >= iconGroupResources->count)
    {
        WINE_WARN("icon index out of range\n");
        goto end;
    }

    iconDirPtr = (NE_NAMEINFO*)(((BYTE*)iconGroupResources) + sizeof(NE_TYPEINFO) + nIndex*sizeof(NE_NAMEINFO));
    if ((((BYTE*)iconDirPtr) + sizeof(NE_NAMEINFO)) > (fileBytes + fileSize))
    {
        WINE_WARN("file too small for icon group NE_NAMEINFO\n");
        goto end;
    }
    iconDir = (GRPICONDIR*)(fileBytes + (iconDirPtr->offset << alignmentShiftCount));
    if ((((BYTE*)iconDir) + sizeof(GRPICONDIR) + iconDir->idCount*sizeof(GRPICONDIRENTRY)) > (fileBytes + fileSize))
    {
        WINE_WARN("file too small for GRPICONDIR\n");
        goto end;
    }

    iconData16.fileBytes = fileBytes;
    iconData16.fileSize = fileSize;
    iconData16.iconResources = iconResources;
    iconData16.alignmentShiftCount = alignmentShiftCount;
    *ppStream = add_module_icons_to_stream(&iconData16, NULL, iconDir);
    if (*ppStream)
        hr = S_OK;

end:
    if (hFile != INVALID_HANDLE_VALUE)
        CloseHandle(hFile);
    if (hFileMapping != NULL)
        CloseHandle(hFileMapping);
    if (fileBytes != NULL)
        UnmapViewOfFile(fileBytes);
    return hr;
}

static BOOL CALLBACK EnumResNameProc(HMODULE hModule, LPCWSTR lpszType, LPWSTR lpszName, LONG_PTR lParam)
{
    ENUMRESSTRUCT *sEnumRes = (ENUMRESSTRUCT *) lParam;

    if (!sEnumRes->nIndex--)
    {
        *sEnumRes->pResInfo = FindResourceW(hModule, lpszName, (LPCWSTR)RT_GROUP_ICON);
        return FALSE;
    }
    else
        return TRUE;
}

static HRESULT open_module_icon(LPCWSTR szFileName, int nIndex, IStream **ppStream)
{
    HMODULE hModule;
    HRSRC hResInfo;
    HGLOBAL hResData;
    GRPICONDIR *pIconDir;
    ENUMRESSTRUCT sEnumRes;
    HRESULT hr = E_FAIL;

    hModule = LoadLibraryExW(szFileName, 0, LOAD_LIBRARY_AS_DATAFILE);
    if (!hModule)
    {
        if (GetLastError() == ERROR_BAD_EXE_FORMAT)
            return open_module16_icon(szFileName, nIndex, ppStream);
        else
        {
            WINE_WARN("LoadLibraryExW (%s) failed, error %d\n",
                     wine_dbgstr_w(szFileName), GetLastError());
            return HRESULT_FROM_WIN32(GetLastError());
        }
    }

    if (nIndex < 0)
    {
        hResInfo = FindResourceW(hModule, MAKEINTRESOURCEW(-nIndex), (LPCWSTR)RT_GROUP_ICON);
        WINE_TRACE("FindResourceW (%s) called, return %p, error %d\n",
                   wine_dbgstr_w(szFileName), hResInfo, GetLastError());
    }
    else
    {
        hResInfo=NULL;
        sEnumRes.pResInfo = &hResInfo;
        sEnumRes.nIndex = nIndex;
        if (!EnumResourceNamesW(hModule, (LPCWSTR)RT_GROUP_ICON,
                                EnumResNameProc, (LONG_PTR)&sEnumRes) &&
            sEnumRes.nIndex != -1)
        {
            WINE_TRACE("EnumResourceNamesW failed, error %d\n", GetLastError());
        }
    }

    if (hResInfo)
    {
        if ((hResData = LoadResource(hModule, hResInfo)))
        {
            if ((pIconDir = LockResource(hResData)))
            {
                *ppStream = add_module_icons_to_stream(0, hModule, pIconDir);
                if (*ppStream)
                    hr = S_OK;
            }

            FreeResource(hResData);
        }
    }
    else
    {
        WINE_WARN("found no icon\n");
        FreeLibrary(hModule);
        return HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
    }

    FreeLibrary(hModule);
    return hr;
}

static HRESULT read_ico_direntries(IStream *icoStream, ICONDIRENTRY **ppIconDirEntries, int *numEntries)
{
    ICONDIR iconDir;
    ULONG bytesRead;
    HRESULT hr;

    *ppIconDirEntries = NULL;

    hr = IStream_Read(icoStream, &iconDir, sizeof(ICONDIR), &bytesRead);
    if (FAILED(hr) || bytesRead != sizeof(ICONDIR) ||
        (iconDir.idReserved != 0) || (iconDir.idType != 1))
    {
        WINE_WARN("Invalid ico file format (hr=0x%08X, bytesRead=%d)\n", hr, bytesRead);
        hr = E_FAIL;
        goto end;
    }
    *numEntries = iconDir.idCount;

    if ((*ppIconDirEntries = HeapAlloc(GetProcessHeap(), 0, sizeof(ICONDIRENTRY)*iconDir.idCount)) == NULL)
    {
        hr = E_OUTOFMEMORY;
        goto end;
    }
    hr = IStream_Read(icoStream, *ppIconDirEntries, sizeof(ICONDIRENTRY)*iconDir.idCount, &bytesRead);
    if (FAILED(hr) || bytesRead != sizeof(ICONDIRENTRY)*iconDir.idCount)
    {
        if (SUCCEEDED(hr)) hr = E_FAIL;
        goto end;
    }

end:
    if (FAILED(hr))
        HeapFree(GetProcessHeap(), 0, *ppIconDirEntries);
    return hr;
}

static HRESULT validate_ico(IStream **ppStream, ICONDIRENTRY **ppIconDirEntries, int *numEntries)
{
    HRESULT hr;

    hr = read_ico_direntries(*ppStream, ppIconDirEntries, numEntries);
    if (SUCCEEDED(hr))
    {
        if (*numEntries)
            return hr;
        HeapFree(GetProcessHeap(), 0, *ppIconDirEntries);
        *ppIconDirEntries = NULL;
    }
    IStream_Release(*ppStream);
    *ppStream = NULL;
    return E_FAIL;
}

static WCHAR* assoc_query(ASSOCSTR assocStr, LPCWSTR name, LPCWSTR extra)
{
    HRESULT hr;
    WCHAR *value = NULL;
    DWORD size = 0;
    hr = AssocQueryStringW(0, assocStr, name, extra, NULL, &size);
    if (SUCCEEDED(hr))
    {
        value = HeapAlloc(GetProcessHeap(), 0, size * sizeof(WCHAR));
        if (value)
        {
            hr = AssocQueryStringW(0, assocStr, name, extra, value, &size);
            if (FAILED(hr))
            {
                HeapFree(GetProcessHeap(), 0, value);
                value = NULL;
            }
        }
    }
    return value;
}

static HRESULT open_file_type_icon(LPCWSTR szFileName, IStream **ppStream)
{
    static const WCHAR openW[] = {'o','p','e','n',0};
    WCHAR *extension;
    WCHAR *icon = NULL;
    WCHAR *comma;
    WCHAR *executable = NULL;
    int index = 0;
    HRESULT hr = HRESULT_FROM_WIN32(ERROR_NOT_FOUND);

    extension = strrchrW(szFileName, '.');
    if (extension == NULL)
        goto end;

    icon = assoc_query(ASSOCSTR_DEFAULTICON, extension, NULL);
    if (icon)
    {
        comma = strrchrW(icon, ',');
        if (comma)
        {
            *comma = 0;
            index = atoiW(comma + 1);
        }
        hr = open_module_icon(icon, index, ppStream);
    }
    else
    {
        executable = assoc_query(ASSOCSTR_EXECUTABLE, extension, openW);
        if (executable)
            hr = open_module_icon(executable, 0, ppStream);
    }

end:
    HeapFree(GetProcessHeap(), 0, icon);
    HeapFree(GetProcessHeap(), 0, executable);
    return hr;
}

static HRESULT open_default_icon(IStream **ppStream)
{
    static const WCHAR user32W[] = {'u','s','e','r','3','2',0};

    return open_module_icon(user32W, -(INT_PTR)IDI_WINLOGO, ppStream);
}

static HRESULT open_icon(LPCWSTR filename, int index, BOOL bWait, IStream **ppStream, ICONDIRENTRY **ppIconDirEntries, int *numEntries)
{
    HRESULT hr;

    hr = open_module_icon(filename, index, ppStream);
    if (FAILED(hr))
    {
        if(bWait && hr == HRESULT_FROM_WIN32(ERROR_MOD_NOT_FOUND))
        {
            WINE_WARN("Can't find file: %s, give a chance to parent process to create it\n",
                                    wine_dbgstr_w(filename));
            return hr;
        }
        else
        {
            /* This might be a raw .ico file */
            hr = SHCreateStreamOnFileW(filename, STGM_READ, ppStream);
        }
    }
    if (SUCCEEDED(hr))
        hr = validate_ico(ppStream, ppIconDirEntries, numEntries);

    if (FAILED(hr))
    {
        hr = open_file_type_icon(filename, ppStream);
        if (SUCCEEDED(hr))
            hr = validate_ico(ppStream, ppIconDirEntries, numEntries);
    }
    if (FAILED(hr) && !bWait)
    {
        hr = open_default_icon(ppStream);
        if (SUCCEEDED(hr))
            hr = validate_ico(ppStream, ppIconDirEntries, numEntries);
    }
    return hr;
}

static char* compute_native_identifier(int exeIndex, LPCWSTR icoPathW)
{
    char* nativeIdentifier;
    char *icoPathA;
    unsigned short crc;
    char *basename, *ext;

    icoPathA = wchars_to_utf8_chars(icoPathW);
    if (icoPathA == NULL)
        return NULL;

    crc = crc16(icoPathA);
    basename = strrchr(icoPathA, '\\');
    if (basename == NULL)
        basename = icoPathA;
    else
    {
        *basename = 0;
        basename++;
    }
    ext = strrchr(basename, '.');
    if (ext)
        *ext = 0;

    nativeIdentifier = heap_printf("%04X_%s.%d", crc, basename, exeIndex);
    HeapFree(GetProcessHeap(), 0, icoPathA);
    return nativeIdentifier;
}

#ifdef __APPLE__
#define ICNS_SLOTS 6

static inline int size_to_slot(int size)
{
    switch (size)
    {
        case 16: return 0;
        case 32: return 1;
        case 48: return 2;
        case 64: return -2;  /* Classic Mode */
        case 128: return 3;
        case 256: return 4;
        case 512: return 5;
    }

    return -1;
}

#define CLASSIC_SLOT 3

static HRESULT platform_write_icon(IStream *icoStream, ICONDIRENTRY *iconDirEntries,
                                   int numEntries, int exeIndex, LPCWSTR icoPathW,
                                   const char *destFilename, char **nativeIdentifier)
{
    struct {
        int index;
        int maxBits;
        BOOL scaled;
    } best[ICNS_SLOTS];
    int indexes[ICNS_SLOTS];
    int i;
    const char* tmpdir;
    char *icnsPath = NULL;
    LARGE_INTEGER zero;
    HRESULT hr;

    for (i = 0; i < ICNS_SLOTS; i++)
    {
        best[i].index = -1;
        best[i].maxBits = 0;
    }
    for (i = 0; i < numEntries; i++)
    {
        int slot;
        int width = iconDirEntries[i].bWidth ? iconDirEntries[i].bWidth : 256;
        int height = iconDirEntries[i].bHeight ? iconDirEntries[i].bHeight : 256;
        BOOL scaled = FALSE;

        WINE_TRACE("[%d]: %d x %d @ %d\n", i, width, height, iconDirEntries[i].wBitCount);
        if (height != width)
            continue;
        slot = size_to_slot(width);
        if (slot == -2)
        {
            scaled = TRUE;
            slot = CLASSIC_SLOT;
        }
        else if (slot < 0)
            continue;
        if (scaled && best[slot].maxBits && !best[slot].scaled)
            continue; /* don't replace unscaled with scaled */
        if (iconDirEntries[i].wBitCount >= best[slot].maxBits || (!scaled && best[slot].scaled))
        {
            best[slot].index = i;
            best[slot].maxBits = iconDirEntries[i].wBitCount;
            best[slot].scaled = scaled;
        }
    }
    /* remove the scaled icon if a larger unscaled icon exists */
    if (best[CLASSIC_SLOT].scaled)
    {
        for (i = CLASSIC_SLOT+1; i < ICNS_SLOTS; i++)
            if (best[i].index >= 0 && !best[i].scaled)
            {
                best[CLASSIC_SLOT].index = -1;
                break;
            }
    }

    numEntries = 0;
    for (i = 0; i < ICNS_SLOTS; i++)
    {
        if (best[i].index >= 0)
        {
            indexes[numEntries] = best[i].index;
            numEntries++;
        }
    }

    if (destFilename)
        *nativeIdentifier = heap_printf("%s", destFilename);
    else
        *nativeIdentifier = compute_native_identifier(exeIndex, icoPathW);
    if (*nativeIdentifier == NULL)
    {
        hr = E_OUTOFMEMORY;
        goto end;
    }
    if (!(tmpdir = getenv("TMPDIR"))) tmpdir = "/tmp";
    icnsPath = heap_printf("%s/%s.icns", tmpdir, *nativeIdentifier);
    if (icnsPath == NULL)
    {
        hr = E_OUTOFMEMORY;
        WINE_WARN("out of memory creating ICNS path\n");
        goto end;
    }
    zero.QuadPart = 0;
    hr = IStream_Seek(icoStream, zero, STREAM_SEEK_SET, NULL);
    if (FAILED(hr))
    {
        WINE_WARN("seeking icon stream failed, error 0x%08X\n", hr);
        goto end;
    }
    hr = convert_to_native_icon(icoStream, indexes, numEntries, &CLSID_WICIcnsEncoder,
                                icnsPath, icoPathW);
    if (FAILED(hr))
    {
        WINE_WARN("converting %s to %s failed, error 0x%08X\n",
            wine_dbgstr_w(icoPathW), wine_dbgstr_a(icnsPath), hr);
        goto end;
    }

end:
    HeapFree(GetProcessHeap(), 0, icnsPath);
    return hr;
}
#else
static void refresh_icon_cache(const char *iconsDir)
{
    /* The icon theme spec only requires the mtime on the "toplevel"
     * directory (whatever that is) to be changed for a refresh,
     * but on GNOME you have to create a file in that directory
     * instead. Creating a file also works on KDE, Xfce and LXDE.
     */
    char *filename = heap_printf("%s/.wine-refresh-XXXXXX", iconsDir);
    if (filename != NULL)
    {
        int fd = mkstemps(filename, 0);
        if (fd >= 0)
        {
            close(fd);
            unlink(filename);
        }
        HeapFree(GetProcessHeap(), 0, filename);
    }
}

static HRESULT platform_write_icon(IStream *icoStream, ICONDIRENTRY *iconDirEntries,
                                   int numEntries, int exeIndex, LPCWSTR icoPathW,
                                   const char *destFilename, char **nativeIdentifier)
{
    int i;
    char *iconsDir = NULL;
    HRESULT hr = S_OK;
    LARGE_INTEGER zero;

    if (destFilename)
        *nativeIdentifier = heap_printf("%s", destFilename);
    else
        *nativeIdentifier = compute_native_identifier(exeIndex, icoPathW);
    if (*nativeIdentifier == NULL)
    {
        hr = E_OUTOFMEMORY;
        goto end;
    }
    iconsDir = heap_printf("%s/icons/hicolor", xdg_data_dir);
    if (iconsDir == NULL)
    {
        hr = E_OUTOFMEMORY;
        goto end;
    }

    for (i = 0; i < numEntries; i++)
    {
        int bestIndex = i;
        int j;
        BOOLEAN duplicate = FALSE;
        int w, h;
        char *iconDir = NULL;
        char *pngPath = NULL;

        WINE_TRACE("[%d]: %d x %d @ %d\n", i, iconDirEntries[i].bWidth,
            iconDirEntries[i].bHeight, iconDirEntries[i].wBitCount);

        for (j = 0; j < i; j++)
        {
            if (iconDirEntries[j].bWidth == iconDirEntries[i].bWidth &&
                iconDirEntries[j].bHeight == iconDirEntries[i].bHeight)
            {
                duplicate = TRUE;
                break;
            }
        }
        if (duplicate)
            continue;
        for (j = i + 1; j < numEntries; j++)
        {
            if (iconDirEntries[j].bWidth == iconDirEntries[i].bWidth &&
                iconDirEntries[j].bHeight == iconDirEntries[i].bHeight &&
                iconDirEntries[j].wBitCount >= iconDirEntries[bestIndex].wBitCount)
            {
                bestIndex = j;
            }
        }
        WINE_TRACE("Selected: %d\n", bestIndex);

        w = iconDirEntries[bestIndex].bWidth ? iconDirEntries[bestIndex].bWidth : 256;
        h = iconDirEntries[bestIndex].bHeight ? iconDirEntries[bestIndex].bHeight : 256;
        iconDir = heap_printf("%s/%dx%d/apps", iconsDir, w, h);
        if (iconDir == NULL)
        {
            hr = E_OUTOFMEMORY;
            goto endloop;
        }
        create_directories(iconDir);
        pngPath = heap_printf("%s/%s.png", iconDir, *nativeIdentifier);
        if (pngPath == NULL)
        {
            hr = E_OUTOFMEMORY;
            goto endloop;
        }
        zero.QuadPart = 0;
        hr = IStream_Seek(icoStream, zero, STREAM_SEEK_SET, NULL);
        if (FAILED(hr))
            goto endloop;
        hr = convert_to_native_icon(icoStream, &bestIndex, 1, &CLSID_WICPngEncoder,
                                    pngPath, icoPathW);

    endloop:
        HeapFree(GetProcessHeap(), 0, iconDir);
        HeapFree(GetProcessHeap(), 0, pngPath);
    }
    refresh_icon_cache(iconsDir);

end:
    HeapFree(GetProcessHeap(), 0, iconsDir);
    return hr;
}
#endif /* defined(__APPLE__) */

/* extract an icon from an exe or icon file; helper for IPersistFile_fnSave */
static char *extract_icon(LPCWSTR icoPathW, int index, const char *destFilename, BOOL bWait)
{
    IStream *stream = NULL;
    ICONDIRENTRY *pIconDirEntries = NULL;
    int numEntries;
    HRESULT hr;
    char *nativeIdentifier = NULL;

    WINE_TRACE("path=[%s] index=%d destFilename=[%s]\n", wine_dbgstr_w(icoPathW), index, wine_dbgstr_a(destFilename));

    hr = open_icon(icoPathW, index, bWait, &stream, &pIconDirEntries, &numEntries);
    if (FAILED(hr))
    {
        WINE_WARN("opening icon %s index %d failed, hr=0x%08X\n", wine_dbgstr_w(icoPathW), index, hr);
        goto end;
    }
    hr = platform_write_icon(stream, pIconDirEntries, numEntries, index, icoPathW, destFilename, &nativeIdentifier);
    if (FAILED(hr))
        WINE_WARN("writing icon failed, error 0x%08X\n", hr);

end:
    if (stream)
        IStream_Release(stream);
    HeapFree(GetProcessHeap(), 0, pIconDirEntries);
    if (FAILED(hr))
    {
        HeapFree(GetProcessHeap(), 0, nativeIdentifier);
        nativeIdentifier = NULL;
    }
    return nativeIdentifier;
}

/* This escapes reserved characters in .desktop files' Exec keys. */
static LPSTR escape(LPCWSTR arg)
{
    int i, j;
    WCHAR *escaped_string;
    char *utf8_string;

    escaped_string = HeapAlloc(GetProcessHeap(), 0, (4 * strlenW(arg) + 1) * sizeof(WCHAR));
    if (escaped_string == NULL) return NULL;
    for (i = j = 0; arg[i]; i++)
    {
        switch (arg[i])
        {
        case '\\':
            escaped_string[j++] = '\\';
            escaped_string[j++] = '\\';
            escaped_string[j++] = '\\';
            escaped_string[j++] = '\\';
            break;
        case ' ':
        case '\t':
        case '\n':
        case '"':
        case '\'':
        case '>':
        case '<':
        case '~':
        case '|':
        case '&':
        case ';':
        case '$':
        case '*':
        case '?':
        case '#':
        case '(':
        case ')':
        case '`':
            escaped_string[j++] = '\\';
            escaped_string[j++] = '\\';
            /* fall through */
        default:
            escaped_string[j++] = arg[i];
            break;
        }
    }
    escaped_string[j] = 0;

    utf8_string = wchars_to_utf8_chars(escaped_string);
    if (utf8_string == NULL)
    {
        WINE_ERR("out of memory\n");
        goto end;
    }

end:
    HeapFree(GetProcessHeap(), 0, escaped_string);
    return utf8_string;
}

static char *slashes_to_minuses(const char *string)
{
    int i;
    char *ret = HeapAlloc(GetProcessHeap(), 0, lstrlenA(string) + 1);
    if (ret)
    {
        for (i = 0; string[i]; i++)
        {
            if (string[i] == '/')
                ret[i] = '-';
            else
                ret[i] = string[i];
        }
        ret[i] = 0;
        return ret;
    }
    return NULL;
}

static BOOL next_line(FILE *file, char **line, int *size)
{
    int pos = 0;
    char *cr;
    if (*line == NULL)
    {
        *size = 4096;
        *line = HeapAlloc(GetProcessHeap(), 0, *size);
    }
    while (*line != NULL)
    {
        if (fgets(&(*line)[pos], *size - pos, file) == NULL)
        {
            HeapFree(GetProcessHeap(), 0, *line);
            *line = NULL;
            if (feof(file))
                return TRUE;
            return FALSE;
        }
        pos = strlen(*line);
        cr = strchr(*line, '\n');
        if (cr == NULL)
        {
            char *line2;
            (*size) *= 2;
            line2 = HeapReAlloc(GetProcessHeap(), 0, *line, *size);
            if (line2)
                *line = line2;
            else
            {
                HeapFree(GetProcessHeap(), 0, *line);
                *line = NULL;
            }
        }
        else
        {
            *cr = 0;
            return TRUE;
        }
    }
    return FALSE;
}

static BOOL add_mimes(const char *xdg_data_dir, struct list *mime_types)
{
    char *globs_filename = NULL;
    BOOL ret = TRUE;
    globs_filename = heap_printf("%s/mime/globs", xdg_data_dir);
    if (globs_filename)
    {
        FILE *globs_file = fopen(globs_filename, "r");
        if (globs_file) /* doesn't have to exist */
        {
            char *line = NULL;
            int size = 0;
            while (ret && (ret = next_line(globs_file, &line, &size)) && line)
            {
                char *pos;
                struct xdg_mime_type *mime_type_entry = NULL;
                if (line[0] != '#' && (pos = strchr(line, ':')))
                {
                    mime_type_entry = HeapAlloc(GetProcessHeap(), 0, sizeof(struct xdg_mime_type));
                    if (mime_type_entry)
                    {
                        *pos = 0;
                        mime_type_entry->mimeType = strdupA(line);
                        mime_type_entry->glob = strdupA(pos + 1);
                        mime_type_entry->lower_glob = strdupA(pos + 1);
                        if (mime_type_entry->lower_glob)
                        {
                            char *l;
                            for (l = mime_type_entry->lower_glob; *l; l++)
                                *l = tolower(*l);
                        }
                        if (mime_type_entry->mimeType && mime_type_entry->glob && mime_type_entry->lower_glob)
                            list_add_tail(mime_types, &mime_type_entry->entry);
                        else
                        {
                            HeapFree(GetProcessHeap(), 0, mime_type_entry->mimeType);
                            HeapFree(GetProcessHeap(), 0, mime_type_entry->glob);
                            HeapFree(GetProcessHeap(), 0, mime_type_entry->lower_glob);
                            HeapFree(GetProcessHeap(), 0, mime_type_entry);
                            ret = FALSE;
                        }
                    }
                    else
                        ret = FALSE;
                }
            }
            HeapFree(GetProcessHeap(), 0, line);
            fclose(globs_file);
        }
        HeapFree(GetProcessHeap(), 0, globs_filename);
    }
    else
        ret = FALSE;
    return ret;
}

static void free_native_mime_types(struct list *native_mime_types)
{
    struct xdg_mime_type *mime_type_entry, *mime_type_entry2;

    LIST_FOR_EACH_ENTRY_SAFE(mime_type_entry, mime_type_entry2, native_mime_types, struct xdg_mime_type, entry)
    {
        list_remove(&mime_type_entry->entry);
        HeapFree(GetProcessHeap(), 0, mime_type_entry->glob);
        HeapFree(GetProcessHeap(), 0, mime_type_entry->lower_glob);
        HeapFree(GetProcessHeap(), 0, mime_type_entry->mimeType);
        HeapFree(GetProcessHeap(), 0, mime_type_entry);
    }
}

BOOL WINAPI winemime_build_native_mime_types(const char *xdg_data_home, struct list *mime_types)
{
    char *xdg_data_dirs;
    BOOL ret;

    xdg_data_dirs = getenv("XDG_DATA_DIRS");
    if (xdg_data_dirs == NULL)
        xdg_data_dirs = heap_printf("/usr/local/share/:/usr/share/");
    else
        xdg_data_dirs = strdupA(xdg_data_dirs);

    if (xdg_data_dirs)
    {
        const char *begin;
        char *end;

        ret = add_mimes(xdg_data_home, mime_types);
        if (ret)
        {
            for (begin = xdg_data_dirs; (end = strchr(begin, ':')); begin = end + 1)
            {
                *end = '\0';
                ret = add_mimes(begin, mime_types);
                *end = ':';
                if (!ret)
                    break;
            }
            if (ret)
                ret = add_mimes(begin, mime_types);
        }
        HeapFree(GetProcessHeap(), 0, xdg_data_dirs);
    }
    else
        ret = FALSE;
    if (!ret)
        free_native_mime_types(mime_types);
    return ret;
}

static BOOL match_glob(struct list *native_mime_types, const char *extension,
                       int ignoreGlobCase, char **match)
{
#ifdef HAVE_FNMATCH
    struct xdg_mime_type *mime_type_entry;
    int matchLength = 0;

    *match = NULL;

    LIST_FOR_EACH_ENTRY(mime_type_entry, native_mime_types, struct xdg_mime_type, entry)
    {
        const char *glob = ignoreGlobCase ? mime_type_entry->lower_glob : mime_type_entry->glob;
        if (fnmatch(glob, extension, 0) == 0)
        {
            if (*match == NULL || matchLength < strlen(glob))
            {
                *match = mime_type_entry->mimeType;
                matchLength = strlen(glob);
            }
        }
    }

    if (*match != NULL)
    {
        *match = strdupA(*match);
        if (*match == NULL)
            return FALSE;
    }
#else
    *match = NULL;
#endif
    return TRUE;
}

static BOOL freedesktop_mime_type_for_extension(struct list *native_mime_types,
                                                const char *extensionA,
                                                LPCWSTR extensionW,
                                                char **mime_type)
{
    WCHAR *lower_extensionW;
    INT len;
    BOOL ret = match_glob(native_mime_types, extensionA, 0, mime_type);
    if (ret == FALSE || *mime_type != NULL)
        return ret;
    len = strlenW(extensionW);
    lower_extensionW = HeapAlloc(GetProcessHeap(), 0, (len + 1)*sizeof(WCHAR));
    if (lower_extensionW)
    {
        char *lower_extensionA;
        memcpy(lower_extensionW, extensionW, (len + 1)*sizeof(WCHAR));
        strlwrW(lower_extensionW);
        lower_extensionA = wchars_to_utf8_chars(lower_extensionW);
        if (lower_extensionA)
        {
            ret = match_glob(native_mime_types, lower_extensionA, 1, mime_type);
            HeapFree(GetProcessHeap(), 0, lower_extensionA);
        }
        else
        {
            ret = FALSE;
            WINE_FIXME("out of memory\n");
        }
        HeapFree(GetProcessHeap(), 0, lower_extensionW);
    }
    else
    {
        ret = FALSE;
        WINE_FIXME("out of memory\n");
    }
    return ret;
}

static const char* get_special_mime_type(LPCWSTR extension);
static BOOL write_freedesktop_mime_type_entry(const char *packages_dir, const char *dot_extension,
                                              const char *mime_type, const char *comment);

BOOL WINAPI winemime_mime_type_for_extension(struct list *native_mime_types,
                                             const WCHAR *extensionW,
                                             const char *packages_dir,
                                             char **mime_type,
                                             BOOL *hasChanged)
{
    BOOL ret = FALSE;
    char *extensionA = NULL;
    WCHAR *lower_extensionW = NULL;
    WCHAR *friendlyDocNameW = NULL;
    char *friendlyDocNameA = NULL;
    WCHAR *iconW = NULL;
    char *iconA = NULL;
    WCHAR *contentTypeW = NULL;
    int len;

    len = strlenW(extensionW);
    lower_extensionW = HeapAlloc(GetProcessHeap(), 0, (len + 1) * sizeof(WCHAR));
    if(lower_extensionW)
    {
        memcpy(lower_extensionW, extensionW, (len + 1) * sizeof(WCHAR));
        strlwrW(lower_extensionW);
        extensionA = wchars_to_utf8_chars(lower_extensionW);
        if (extensionA == NULL)
        {
            WINE_ERR("out of memory\n");
            goto end;
        }
    }
    else
    {
        WINE_ERR("out of memory\n");
        goto end;
    }

    friendlyDocNameW = assoc_query(ASSOCSTR_FRIENDLYDOCNAME, extensionW, NULL);
    if (friendlyDocNameW)
    {
        friendlyDocNameA = wchars_to_utf8_chars(friendlyDocNameW);
        if (friendlyDocNameA == NULL)
        {
            WINE_ERR("out of memory\n");
            goto end;
        }
    }

    iconW = assoc_query(ASSOCSTR_DEFAULTICON, extensionW, NULL);

    contentTypeW = assoc_query(ASSOCSTR_CONTENTTYPE, extensionW, NULL);
    if (contentTypeW)
        strlwrW(contentTypeW);

    if (!freedesktop_mime_type_for_extension(native_mime_types, extensionA, extensionW, mime_type))
        goto end;

    if (*mime_type == NULL)
    {
        if (contentTypeW != NULL && strchrW(contentTypeW, '/'))
            *mime_type = wchars_to_utf8_chars(contentTypeW);
        else if ((get_special_mime_type(extensionW)))
            *mime_type = strdupA(get_special_mime_type(extensionW));
        else
            *mime_type = heap_printf("application/x-wine-extension-%s", &extensionA[1]);

        if (*mime_type != NULL)
        {
            /* GNOME seems to ignore the <icon> tag in MIME packages,
             * and the default name is more intuitive anyway.
             */
            if (iconW)
            {
                char *flattened_mime = slashes_to_minuses(*mime_type);
                if (flattened_mime)
                {
                    int index = 0;
                    WCHAR *comma = strrchrW(iconW, ',');
                    if (comma)
                    {
                        *comma = 0;
                        index = atoiW(comma + 1);
                    }
                    iconA = extract_icon(iconW, index, flattened_mime, FALSE);
                    HeapFree(GetProcessHeap(), 0, flattened_mime);
                }
            }

            write_freedesktop_mime_type_entry(packages_dir, extensionA, *mime_type, friendlyDocNameA);
            *hasChanged = TRUE;
        }
        else
        {
            WINE_FIXME("out of memory\n");
            goto end;
        }
    }

    ret = TRUE;

end:
    HeapFree(GetProcessHeap(), 0, extensionA);
    HeapFree(GetProcessHeap(), 0, friendlyDocNameW);
    HeapFree(GetProcessHeap(), 0, friendlyDocNameA);
    HeapFree(GetProcessHeap(), 0, iconW);
    HeapFree(GetProcessHeap(), 0, iconA);
    HeapFree(GetProcessHeap(), 0, contentTypeW);

    return ret;
}

static WCHAR* reg_get_valW(HKEY key, LPCWSTR subkey, LPCWSTR name)
{
    DWORD size;
    if (RegGetValueW(key, subkey, name, RRF_RT_REG_SZ, NULL, NULL, &size) == ERROR_SUCCESS)
    {
        WCHAR *ret = HeapAlloc(GetProcessHeap(), 0, size);
        if (ret)
        {
            if (RegGetValueW(key, subkey, name, RRF_RT_REG_SZ, NULL, ret, &size) == ERROR_SUCCESS)
                return ret;
        }
        HeapFree(GetProcessHeap(), 0, ret);
    }
    return NULL;
}

static CHAR* reg_get_val_utf8(HKEY key, LPCWSTR subkey, LPCWSTR name)
{
    WCHAR *valW = reg_get_valW(key, subkey, name);
    if (valW)
    {
        char *val = wchars_to_utf8_chars(valW);
        HeapFree(GetProcessHeap(), 0, valW);
        return val;
    }
    return NULL;
}

static HKEY open_associations_reg_key(void)
{
    static const WCHAR Software_Wine_FileOpenAssociationsW[] = {
        'S','o','f','t','w','a','r','e','\\','W','i','n','e','\\','F','i','l','e','O','p','e','n','A','s','s','o','c','i','a','t','i','o','n','s',0};
    HKEY assocKey;
    if (RegCreateKeyW(HKEY_CURRENT_USER, Software_Wine_FileOpenAssociationsW, &assocKey) == ERROR_SUCCESS)
        return assocKey;
    return NULL;
}

static BOOL has_association_changed(LPCWSTR extensionW, LPCSTR mimeType, LPCWSTR progId,
    LPCSTR appName, LPCSTR openWithIcon)
{
    static const WCHAR ProgIDW[] = {'P','r','o','g','I','D',0};
    static const WCHAR MimeTypeW[] = {'M','i','m','e','T','y','p','e',0};
    static const WCHAR AppNameW[] = {'A','p','p','N','a','m','e',0};
    static const WCHAR OpenWithIconW[] = {'O','p','e','n','W','i','t','h','I','c','o','n',0};
    HKEY assocKey;
    BOOL ret;

    if ((assocKey = open_associations_reg_key()))
    {
        CHAR *valueA;
        WCHAR *value;

        ret = FALSE;

        valueA = reg_get_val_utf8(assocKey, extensionW, MimeTypeW);
        if (!valueA || lstrcmpA(valueA, mimeType))
            ret = TRUE;
        HeapFree(GetProcessHeap(), 0, valueA);

        value = reg_get_valW(assocKey, extensionW, ProgIDW);
        if (!value || strcmpW(value, progId))
            ret = TRUE;
        HeapFree(GetProcessHeap(), 0, value);

        valueA = reg_get_val_utf8(assocKey, extensionW, AppNameW);
        if (!valueA || lstrcmpA(valueA, appName))
            ret = TRUE;
        HeapFree(GetProcessHeap(), 0, valueA);

        valueA = reg_get_val_utf8(assocKey, extensionW, OpenWithIconW);
        if ((openWithIcon && !valueA) ||
            (!openWithIcon && valueA) ||
            (openWithIcon && valueA && lstrcmpA(valueA, openWithIcon)))
            ret = TRUE;
        HeapFree(GetProcessHeap(), 0, valueA);

        RegCloseKey(assocKey);
    }
    else
    {
        WINE_ERR("error opening associations registry key\n");
        ret = FALSE;
    }
    return ret;
}

static void update_association(LPCWSTR extension, LPCSTR mimeType, LPCWSTR progId,
    LPCSTR appName, LPCSTR desktopFile, LPCSTR openWithIcon)
{
    static const WCHAR ProgIDW[] = {'P','r','o','g','I','D',0};
    static const WCHAR MimeTypeW[] = {'M','i','m','e','T','y','p','e',0};
    static const WCHAR AppNameW[] = {'A','p','p','N','a','m','e',0};
    static const WCHAR DesktopFileW[] = {'D','e','s','k','t','o','p','F','i','l','e',0};
    static const WCHAR OpenWithIconW[] = {'O','p','e','n','W','i','t','h','I','c','o','n',0};
    HKEY assocKey = NULL;
    HKEY subkey = NULL;
    WCHAR *mimeTypeW = NULL;
    WCHAR *appNameW = NULL;
    WCHAR *desktopFileW = NULL;
    WCHAR *openWithIconW = NULL;

    assocKey = open_associations_reg_key();
    if (assocKey == NULL)
    {
        WINE_ERR("could not open file associations key\n");
        goto done;
    }

    if (RegCreateKeyW(assocKey, extension, &subkey) != ERROR_SUCCESS)
    {
        WINE_ERR("could not create extension subkey\n");
        goto done;
    }

    mimeTypeW = utf8_chars_to_wchars(mimeType);
    if (mimeTypeW == NULL)
    {
        WINE_ERR("out of memory\n");
        goto done;
    }

    appNameW = utf8_chars_to_wchars(appName);
    if (appNameW == NULL)
    {
        WINE_ERR("out of memory\n");
        goto done;
    }

    desktopFileW = utf8_chars_to_wchars(desktopFile);
    if (desktopFileW == NULL)
    {
        WINE_ERR("out of memory\n");
        goto done;
    }

    if (openWithIcon)
    {
        openWithIconW = utf8_chars_to_wchars(openWithIcon);
        if (openWithIconW == NULL)
        {
            WINE_ERR("out of memory\n");
            goto done;
        }
    }

    RegSetValueExW(subkey, MimeTypeW, 0, REG_SZ, (const BYTE*) mimeTypeW, (lstrlenW(mimeTypeW) + 1) * sizeof(WCHAR));
    RegSetValueExW(subkey, ProgIDW, 0, REG_SZ, (const BYTE*) progId, (lstrlenW(progId) + 1) * sizeof(WCHAR));
    RegSetValueExW(subkey, AppNameW, 0, REG_SZ, (const BYTE*) appNameW, (lstrlenW(appNameW) + 1) * sizeof(WCHAR));
    RegSetValueExW(subkey, DesktopFileW, 0, REG_SZ, (const BYTE*) desktopFileW, (lstrlenW(desktopFileW) + 1) * sizeof(WCHAR));
    if (openWithIcon)
        RegSetValueExW(subkey, OpenWithIconW, 0, REG_SZ, (const BYTE*) openWithIconW, (lstrlenW(openWithIconW) + 1) * sizeof(WCHAR));
    else
        RegDeleteValueW(subkey, OpenWithIconW);

done:
    RegCloseKey(assocKey);
    RegCloseKey(subkey);
    HeapFree(GetProcessHeap(), 0, mimeTypeW);
    HeapFree(GetProcessHeap(), 0, appNameW);
    HeapFree(GetProcessHeap(), 0, desktopFileW);
    HeapFree(GetProcessHeap(), 0, openWithIconW);
}

static BOOL is_extension_blacklisted(LPCWSTR extension);
typedef HRESULT(*EXTENSION_KEY_HANDLER)(const WCHAR *extensionW, void *user_data);

HRESULT WINAPI winemime_enumerate_registry_extensions(HKEY ext_key, EXTENSION_KEY_HANDLER ext_handler, void *user_data)
{
    int i;
    HRESULT ret = S_OK;
    WCHAR *extensionW = NULL;

    for (i = 0; ; ++i)
    {
        DWORD size = 1024;
        LSTATUS ret_status;

        do
        {
            HeapFree(GetProcessHeap(), 0, extensionW);
            extensionW = HeapAlloc(GetProcessHeap(), 0, size * sizeof(WCHAR));
            if (extensionW == NULL)
            {
                WINE_ERR("out of memory\n");
                ret_status = ERROR_OUTOFMEMORY;
                break;
            }
            ret_status = RegEnumKeyExW(ext_key, i, extensionW, &size, NULL, NULL, NULL, NULL);
            size *= 2;
        } while (ret_status == ERROR_MORE_DATA);


        if(ret_status != ERROR_SUCCESS)
        {
            if(ret_status != ERROR_NO_MORE_ITEMS)
                ret = E_FAIL;
            break;
        }

        if (extensionW[0] == '.' && !is_extension_blacklisted(extensionW))
        {
            ret = ext_handler(extensionW, user_data);
            if(ret != S_OK)
                break;
        }
        else
            continue;
    }

    HeapFree(GetProcessHeap(), 0, extensionW);

    return ret;
}

BOOL WINAPI winemime_remove_mime_association(const WCHAR *extensionW)
{
    static const WCHAR DesktopFileW[] = {'D','e','s','k','t','o','p','F','i','l','e',0};
    HKEY assocKey;
    HKEY extKey;
    BOOL hasChanged = FALSE;

    if ((assocKey = open_associations_reg_key()))
    {
        if (RegOpenKeyW(assocKey, extensionW, &extKey) == ERROR_SUCCESS)
        {
            char *desktopFile = reg_get_val_utf8(assocKey, extensionW, DesktopFileW);
            if (desktopFile)
            {
                WINE_TRACE("removing file type association for %s\n", wine_dbgstr_w(extensionW));
                remove(desktopFile);
            }
            RegDeleteKeyW(assocKey, extensionW);
            hasChanged = TRUE;
            RegCloseKey(extKey);
            HeapFree(GetProcessHeap(), 0, desktopFile);
        }
        else
            WINE_ERR("could not open extension subkey\n");
        RegCloseKey(assocKey);
    }
    else
        WINE_ERR("could not open file associations key\n");

    return hasChanged;
}

static BOOL write_freedesktop_mime_type_entry(const char *packages_dir, const char *dot_extension,
                                              const char *mime_type, const char *comment)
{
    BOOL ret = FALSE;
    char *filename;

    WINE_TRACE("writing MIME type %s, extension=%s, comment=%s\n", wine_dbgstr_a(mime_type),
               wine_dbgstr_a(dot_extension), wine_dbgstr_a(comment));

    filename = heap_printf("%s/x-wine-extension-%s.xml", packages_dir, &dot_extension[1]);
    if (filename)
    {
        FILE *packageFile = fopen(filename, "w");
        if (packageFile)
        {
            fprintf(packageFile, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
            fprintf(packageFile, "<mime-info xmlns=\"http://www.freedesktop.org/standards/shared-mime-info\">\n");
            fprintf(packageFile, "  <mime-type type=\"");
            write_xml_text(packageFile, mime_type);
            fprintf(packageFile, "\">\n");
            fprintf(packageFile, "    <glob pattern=\"*");
            write_xml_text(packageFile, dot_extension);
            fprintf(packageFile, "\"/>\n");
            if (comment)
            {
                fprintf(packageFile, "    <comment>");
                write_xml_text(packageFile, comment);
                fprintf(packageFile, "</comment>\n");
            }
            fprintf(packageFile, "  </mime-type>\n");
            fprintf(packageFile, "</mime-info>\n");
            ret = TRUE;
            fclose(packageFile);
        }
        else
            WINE_ERR("error writing file %s\n", filename);
        HeapFree(GetProcessHeap(), 0, filename);
    }
    else
        WINE_ERR("out of memory\n");
    return ret;
}

static BOOL is_extension_blacklisted(LPCWSTR extension)
{
    /* These are managed through external tools like wine.desktop, to evade malware created file type associations */
    static const WCHAR comW[] = {'.','c','o','m',0};
    static const WCHAR exeW[] = {'.','e','x','e',0};
    static const WCHAR msiW[] = {'.','m','s','i',0};

    if (!strcmpiW(extension, comW) ||
        !strcmpiW(extension, exeW) ||
        !strcmpiW(extension, msiW))
        return TRUE;
    return FALSE;
}

static const char* get_special_mime_type(LPCWSTR extension)
{
    static const WCHAR lnkW[] = {'.','l','n','k',0};
    if (!strcmpiW(extension, lnkW))
        return "application/x-ms-shortcut";
    return NULL;
}

static BOOL write_freedesktop_association_entry(const char *desktopPath, const char *dot_extension,
                                                const char *friendlyAppName, const char *mimeType,
                                                const char *progId, const char *openWithIcon)
{
    BOOL ret = FALSE;
    FILE *desktop;

    WINE_TRACE("writing association for file type %s, friendlyAppName=%s, MIME type %s, progID=%s, icon=%s to file %s\n",
               wine_dbgstr_a(dot_extension), wine_dbgstr_a(friendlyAppName), wine_dbgstr_a(mimeType),
               wine_dbgstr_a(progId), wine_dbgstr_a(openWithIcon), wine_dbgstr_a(desktopPath));

    desktop = fopen(desktopPath, "w");
    if (desktop)
    {
        fprintf(desktop, "[Desktop Entry]\n");
        fprintf(desktop, "Type=Application\n");
        fprintf(desktop, "Name=%s\n", friendlyAppName);
        fprintf(desktop, "MimeType=%s;\n", mimeType);
        fprintf(desktop, "Exec=env WINEPREFIX=\"%s\" wine start /ProgIDOpen %s %%f\n", wine_get_config_dir(), progId);
        fprintf(desktop, "NoDisplay=true\n");
        fprintf(desktop, "StartupNotify=true\n");
        if (openWithIcon)
            fprintf(desktop, "Icon=%s\n", openWithIcon);
        ret = TRUE;
        fclose(desktop);
    }
    else
        WINE_ERR("error writing association file %s\n", wine_dbgstr_a(desktopPath));
    return ret;
}

BOOL WINAPI winemime_add_mime_association(const WCHAR *extensionW, const char *mime_typeA,
    const WCHAR *prog_idW, const char *applications_dir, BOOL *has_native_mimes_changed)
{
    static const WCHAR openW[] = {'o','p','e','n',0};
    BOOL ret = FALSE;
    char *extensionA = NULL;
    WCHAR *lower_extensionW = NULL;
    WCHAR *executableW = NULL;
    char *openWithIconA = NULL;
    WCHAR *friendlyAppNameW = NULL;
    char *friendlyAppNameA = NULL;
    char *progIdA = NULL;
    int len;

    len = strlenW(extensionW);
    lower_extensionW = HeapAlloc(GetProcessHeap(), 0, (len + 1) * sizeof(WCHAR));
    if(lower_extensionW)
    {
        memcpy(lower_extensionW, extensionW, (len + 1) * sizeof(WCHAR));
        strlwrW(lower_extensionW);
        extensionA = wchars_to_utf8_chars(lower_extensionW);
        if (extensionA == NULL)
        {
            WINE_ERR("out of memory\n");
            goto end;
        }
    }
    else
    {
        WINE_ERR("out of memory\n");
        goto end;
    }

    if (prog_idW)
    {
        progIdA = escape(prog_idW);
        if (progIdA == NULL)
        {
            WINE_ERR("out of memory\n");
            goto end;
        }
    }
    else
        goto end; /* no progID => not a file type association */

    executableW = assoc_query(ASSOCSTR_EXECUTABLE, extensionW, openW);
    if (executableW)
        openWithIconA = extract_icon(executableW, 0, NULL, FALSE);

    friendlyAppNameW = assoc_query(ASSOCSTR_FRIENDLYAPPNAME, extensionW, openW);
    if (friendlyAppNameW)
    {
        friendlyAppNameA = wchars_to_utf8_chars(friendlyAppNameW);
        if (friendlyAppNameA == NULL)
        {
            WINE_ERR("out of memory\n");
            goto end;
        }
    }
    else
    {
        friendlyAppNameA = heap_printf("A Wine application");
        if (friendlyAppNameA == NULL)
        {
            WINE_ERR("out of memory\n");
            goto end;
        }
    }

    if (has_association_changed(extensionW, mime_typeA, prog_idW, friendlyAppNameA, openWithIconA))
    {
        char *desktopPath = heap_printf("%s/wine-extension-%s.desktop", applications_dir, &extensionA[1]);
        if (desktopPath)
        {
            if (write_freedesktop_association_entry(desktopPath, extensionA, friendlyAppNameA, mime_typeA, progIdA, openWithIconA))
            {
                *has_native_mimes_changed = TRUE;
                update_association(extensionW, mime_typeA, prog_idW, friendlyAppNameA, desktopPath, openWithIconA);
            }
            HeapFree(GetProcessHeap(), 0, desktopPath);
        }
    }

    ret = TRUE;

end:
    HeapFree(GetProcessHeap(), 0, extensionA);
    HeapFree(GetProcessHeap(), 0, executableW);
    HeapFree(GetProcessHeap(), 0, openWithIconA);
    HeapFree(GetProcessHeap(), 0, friendlyAppNameW);
    HeapFree(GetProcessHeap(), 0, friendlyAppNameA);

    return ret;
}

static BOOL init_xdg(void)
{
    WCHAR shellDesktopPath[MAX_PATH];
    HRESULT hr = SHGetFolderPathW(NULL, CSIDL_DESKTOP, NULL, SHGFP_TYPE_CURRENT, shellDesktopPath);
    if (SUCCEEDED(hr))
        xdg_desktop_dir = wine_get_unix_file_name(shellDesktopPath);
    if (xdg_desktop_dir == NULL)
    {
        WINE_ERR("error looking up the desktop directory\n");
        return FALSE;
    }

    if (getenv("XDG_CONFIG_HOME"))
        xdg_config_dir = heap_printf("%s/menus/applications-merged", getenv("XDG_CONFIG_HOME"));
    else
        xdg_config_dir = heap_printf("%s/.config/menus/applications-merged", getenv("HOME"));
    if (xdg_config_dir)
    {
        create_directories(xdg_config_dir);
        if (getenv("XDG_DATA_HOME"))
            xdg_data_dir = strdupA(getenv("XDG_DATA_HOME"));
        else
            xdg_data_dir = heap_printf("%s/.local/share", getenv("HOME"));
        if (xdg_data_dir)
        {
            char *buffer;
            create_directories(xdg_data_dir);
            buffer = heap_printf("%s/desktop-directories", xdg_data_dir);
            if (buffer)
            {
                mkdir(buffer, 0777);
                HeapFree(GetProcessHeap(), 0, buffer);
            }
            return TRUE;
        }
        HeapFree(GetProcessHeap(), 0, xdg_config_dir);
    }
    WINE_ERR("out of memory\n");
    return FALSE;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD reason, LPVOID reserved)
{
    switch(reason)
    {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            break;
    }
    init_xdg();

    return TRUE;
}
