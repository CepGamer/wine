/*
 * GStreamer splitter + decoder, adapted from parser.c
 *
 * Copyright 2010 Maarten Lankhorst for CodeWeavers
 * Copyright 2010 Aric Stewart for CodeWeavers
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
#include <gst/app/gstappsink.h>
#include <gst/app/gstappsrc.h>
#include <gst/app/gstappbuffer.h>
#include <gst/gstutils.h>

#include "gst_private.h"
#include "gst_guids.h"

#include "vfwmsgs.h"
#include "amvideo.h"

#include "wine/unicode.h"
#include "wine/debug.h"

#include <assert.h>

#include "dvdmedia.h"
#include "mmreg.h"
#include "ks.h"
#include "initguid.h"
#include "ksmedia.h"

WINE_DEFAULT_DEBUG_CHANNEL(gstreamer);

typedef struct GSTOutPin GSTOutPin;
typedef struct GSTInPin {
    BasePin pin;
    IAsyncReader *pReader;
    IMemAllocator *pAlloc;
} GSTInPin;

typedef struct GSTImpl {
    BaseFilter filter;

    GSTInPin pInputPin;
    GSTOutPin **ppPins;
    LONG cStreams;
    SourceSeeking sourceSeeking;

    LONGLONG filesize;

    BOOL discont, initial;
    GstElement *gstfilter;
    GstPad *my_src, *their_sink;
    GstBus *bus;
    guint64 start, nextofs, nextpullofs, stop;
    ALLOCATOR_PROPERTIES props;
    HANDLE event, changed_ofs;
} GSTImpl;

struct GSTOutPin {
    BaseOutputPin pin;

    GstPad *their_src;
    GstPad *my_sink;
    int isaud, isvid;
    AM_MEDIA_TYPE * pmt;
    HANDLE caps_event;
};

static const WCHAR wcsInputPinName[] = {'i','n','p','u','t',' ','p','i','n',0};
static const IMediaSeekingVtbl GST_Seeking_Vtbl;
static const IPinVtbl GST_OutputPin_Vtbl;
static const IPinVtbl GST_InputPin_Vtbl;
static const IBaseFilterVtbl GST_Vtbl;

static HRESULT GST_AddPin(GSTImpl *This, const PIN_INFO *piOutput, const AM_MEDIA_TYPE *amt);
static HRESULT GST_RemoveOutputPins(GSTImpl *This);
static HRESULT WINAPI GST_ChangeCurrent(IMediaSeeking *iface);
static HRESULT WINAPI GST_ChangeStop(IMediaSeeking *iface);
static HRESULT WINAPI GST_ChangeRate(IMediaSeeking *iface);

static int amt_from_gst_caps_audio(GstCaps *caps, AM_MEDIA_TYPE *amt) {
    WAVEFORMATEXTENSIBLE *wfe;
    WAVEFORMATEX *wfx;
    GstStructure *arg;
    gint32 depth = 0, bpp = 0;
    const char *typename;
    arg = gst_caps_get_structure(caps, 0);
    typename = gst_structure_get_name(arg);
    if (!typename)
        return 0;

    wfe = CoTaskMemAlloc(sizeof(*wfe));
    wfx = (WAVEFORMATEX*)wfe;
    amt->majortype = MEDIATYPE_Audio;
    amt->subtype = MEDIASUBTYPE_PCM;
    amt->formattype = FORMAT_WaveFormatEx;
    amt->pbFormat = (BYTE*)wfe;
    amt->cbFormat = sizeof(*wfe);
    amt->bFixedSizeSamples = 0;
    amt->bTemporalCompression = 1;
    amt->lSampleSize = 0;
    amt->pUnk = NULL;

    wfx->wFormatTag = WAVE_FORMAT_EXTENSIBLE;
    if (!gst_structure_get_int(arg, "channels", (INT*)&wfx->nChannels))
        return 0;
    if (!gst_structure_get_int(arg, "rate", (INT*)&wfx->nSamplesPerSec))
        return 0;
    gst_structure_get_int(arg, "width", &depth);
    gst_structure_get_int(arg, "depth", &bpp);
    if (!depth || depth > 32 || depth % 8)
        depth = bpp;
    else if (!bpp)
        bpp = depth;
    wfe->Samples.wValidBitsPerSample = depth;
    wfx->wBitsPerSample = bpp;
    wfx->cbSize = sizeof(*wfe)-sizeof(*wfx);
    switch (wfx->nChannels) {
        case 1: wfe->dwChannelMask = KSAUDIO_SPEAKER_MONO; break;
        case 2: wfe->dwChannelMask = KSAUDIO_SPEAKER_STEREO; break;
        case 4: wfe->dwChannelMask = KSAUDIO_SPEAKER_SURROUND; break;
        case 5: wfe->dwChannelMask = (KSAUDIO_SPEAKER_5POINT1 & ~SPEAKER_LOW_FREQUENCY); break;
        case 6: wfe->dwChannelMask = KSAUDIO_SPEAKER_5POINT1; break;
        case 8: wfe->dwChannelMask = KSAUDIO_SPEAKER_7POINT1; break;
        default:
        wfe->dwChannelMask = 0;
    }
    if (!strcmp(typename, "audio/x-raw-float")) {
        wfe->SubFormat = KSDATAFORMAT_SUBTYPE_IEEE_FLOAT;
        wfx->wBitsPerSample = wfe->Samples.wValidBitsPerSample = 32;
    } else
        wfe->SubFormat = KSDATAFORMAT_SUBTYPE_PCM;
    wfx->nBlockAlign = wfx->nChannels * wfx->wBitsPerSample/8;
    wfx->nAvgBytesPerSec = wfx->nSamplesPerSec * wfx->nBlockAlign;
    return 1;
}

static int amt_from_gst_caps_video(GstCaps *caps, AM_MEDIA_TYPE *amt) {
    VIDEOINFOHEADER *vih = CoTaskMemAlloc(sizeof(*vih));
    BITMAPINFOHEADER *bih = &vih->bmiHeader;
    GstStructure *arg;
    gint32 width = 0, height = 0, nom = 0, denom = 0;
    const char *typename;
    arg = gst_caps_get_structure(caps, 0);
    typename = gst_structure_get_name(arg);
    if (!typename)
        return 0;
    if (!gst_structure_get_int(arg, "width", &width) ||
        !gst_structure_get_int(arg, "height", &height) ||
        !gst_structure_get_fraction(arg, "framerate", &nom, &denom))
        return 0;
    amt->formattype = FORMAT_VideoInfo;
    amt->pbFormat = (BYTE*)vih;
    amt->cbFormat = sizeof(*vih);
    amt->bFixedSizeSamples = amt->bTemporalCompression = 1;
    amt->lSampleSize = 0;
    amt->pUnk = NULL;
    ZeroMemory(vih, sizeof(*vih));
    amt->majortype = MEDIATYPE_Video;
    if (!strcmp(typename, "video/x-raw-rgb")) {
        if (!gst_structure_get_int(arg, "bpp", (INT*)&bih->biBitCount))
            return 0;
        switch (bih->biBitCount) {
            case 16: amt->subtype = MEDIASUBTYPE_RGB555; break;
            case 24: amt->subtype = MEDIASUBTYPE_RGB24; break;
            case 32: amt->subtype = MEDIASUBTYPE_RGB32; break;
            default:
                FIXME("Unknown bpp %u\n", bih->biBitCount);
                return 0;
        }
        bih->biCompression = BI_RGB;
    } else {
        amt->subtype = MEDIATYPE_Video;
        if (!gst_structure_get_fourcc(arg, "format", &amt->subtype.Data1))
            return 0;
        switch (amt->subtype.Data1) {
            case mmioFOURCC('I','4','2','0'):
            case mmioFOURCC('Y','V','1','2'):
            case mmioFOURCC('N','V','1','2'):
            case mmioFOURCC('N','V','2','1'):
                bih->biBitCount = 12; break;
            case mmioFOURCC('Y','U','Y','2'):
            case mmioFOURCC('Y','V','Y','U'):
                bih->biBitCount = 16; break;
        }
        bih->biCompression = amt->subtype.Data1;
    }
    bih->biSizeImage = width * height * bih->biBitCount / 8;
    vih->AvgTimePerFrame = 10000000;
    vih->AvgTimePerFrame *= denom;
    vih->AvgTimePerFrame /= nom;
    vih->rcSource.left = 0;
    vih->rcSource.right = width;
    vih->rcSource.top = height;
    vih->rcSource.bottom = 0;
    vih->rcTarget = vih->rcSource;
    bih->biSize = sizeof(*bih);
    bih->biWidth = width;
    bih->biHeight = height;
    bih->biPlanes = 1;
    return 1;
}

static gboolean accept_caps_sink(GstPad *pad, GstCaps *caps) {
    GSTOutPin *pin = gst_pad_get_element_private(pad);
    AM_MEDIA_TYPE amt;
    GstStructure *arg;
    const char *typename;
    int ret;
    arg = gst_caps_get_structure(caps, 0);
    typename = gst_structure_get_name(arg);
    if (!strcmp(typename, "audio/x-raw-int") ||
        !strcmp(typename, "audio/x-raw-float")) {
        if (!pin->isaud) {
            ERR("Setting audio caps on non-audio pad?\n");
            return 0;
        }
        ret = amt_from_gst_caps_audio(caps, &amt);
        FreeMediaType(&amt);
        TRACE("+%i\n", ret);
        return ret;
    } else if (!strcmp(typename, "video/x-raw-rgb")
               || !strcmp(typename, "video/x-raw-yuv")) {
        if (!pin->isvid) {
            ERR("Setting video caps on non-video pad?\n");
            return 0;
        }
        ret = amt_from_gst_caps_video(caps, &amt);
        FreeMediaType(&amt);
        TRACE("-%i\n", ret);
        return ret;
    } else {
        FIXME("Unhandled type \"%s\"\n", typename);
        return 0;
    }
}

static gboolean setcaps_sink(GstPad *pad, GstCaps *caps) {
    GSTOutPin *pin = gst_pad_get_element_private(pad);
    GSTImpl *This = (GSTImpl *)pin->pin.pin.pinInfo.pFilter;
    AM_MEDIA_TYPE amt;
    GstStructure *arg;
    const char *typename;
    int ret;
    arg = gst_caps_get_structure(caps, 0);
    typename = gst_structure_get_name(arg);
    if (!strcmp(typename, "audio/x-raw-int") ||
        !strcmp(typename, "audio/x-raw-float")) {
        if (!pin->isaud) {
            ERR("Setting audio caps on non-audio pad?\n");
            return 0;
        }
        ret = amt_from_gst_caps_audio(caps, &amt);
    } else if (!strcmp(typename, "video/x-raw-rgb")
               || !strcmp(typename, "video/x-raw-yuv")) {
        if (!pin->isvid) {
            ERR("Setting video caps on non-video pad?\n");
            return 0;
        }
        ret = amt_from_gst_caps_video(caps, &amt);
        if (ret)
            This->props.cbBuffer = max(This->props.cbBuffer, ((VIDEOINFOHEADER*)amt.pbFormat)->bmiHeader.biSizeImage);
    } else {
        FIXME("Unhandled type \"%s\"\n", typename);
        return 0;
    }
    TRACE("Linking returned %i for %s\n", ret, typename);
    if (!ret)
        return 0;
    FreeMediaType(pin->pmt);
    *pin->pmt = amt;
    return 1;
}

static gboolean gst_base_src_perform_seek(GSTImpl *This, GstEvent *event)
{
    gboolean res = TRUE;
    gdouble rate;
    GstFormat seek_format;
    GstSeekFlags flags;
    GstSeekType cur_type, stop_type;
    gint64 cur, stop;
    gboolean flush;
    guint32 seqnum;
    GstEvent *tevent;

    gst_event_parse_seek(event, &rate, &seek_format, &flags,
                         &cur_type, &cur, &stop_type, &stop);

    if (seek_format != GST_FORMAT_BYTES) {
        FIXME("Not handling other format %i\n", seek_format);
        return 0;
    }

    flush = flags & GST_SEEK_FLAG_FLUSH;
    seqnum = gst_event_get_seqnum(event);

    /* send flush start */
    if (flush) {
        tevent = gst_event_new_flush_start();
        gst_event_set_seqnum(tevent, seqnum);
        gst_pad_push_event(This->my_src, tevent);
        if (This->pInputPin.pReader)
            IAsyncReader_BeginFlush(This->pInputPin.pReader);
    }

    TRACE("++++++++++++++++ perform byte seek ------------------\n");

    /* and prepare to continue streaming */
    if (flush) {
        tevent = gst_event_new_flush_stop();
        gst_event_set_seqnum(tevent, seqnum);
        gst_pad_push_event(This->my_src, tevent);
        if (This->pInputPin.pReader)
            IAsyncReader_EndFlush(This->pInputPin.pReader);
    }

    return res;
}

static gboolean event_src(GstPad *pad, GstEvent *event) {
    GSTImpl *This = gst_pad_get_element_private(pad);
    switch (event->type) {
        case GST_EVENT_SEEK:
            return gst_base_src_perform_seek(This, event);
        case GST_EVENT_FLUSH_START:
            EnterCriticalSection(&This->filter.csFilter);
            if (This->pInputPin.pReader)
                IAsyncReader_BeginFlush(This->pInputPin.pReader);
            LeaveCriticalSection(&This->filter.csFilter);
            break;
        case GST_EVENT_FLUSH_STOP:
            EnterCriticalSection(&This->filter.csFilter);
            if (This->pInputPin.pReader)
                IAsyncReader_EndFlush(This->pInputPin.pReader);
            LeaveCriticalSection(&This->filter.csFilter);
            break;
        default:
            FIXME("%p stub\n", event);
            return gst_pad_event_default(pad, event);
    }
    return 1;
}

static gboolean event_sink(GstPad *pad, GstEvent *event) {
    GSTOutPin *pin = gst_pad_get_element_private(pad);
    switch (event->type) {
        case GST_EVENT_NEWSEGMENT: {
            gboolean update;
            gdouble rate, applied_rate;
            GstFormat format;
            gint64 start, stop, pos;
            gst_event_parse_new_segment_full(event, &update, &rate, &applied_rate, &format, &start, &stop, &pos);
            if (format != GST_FORMAT_TIME) {
                FIXME("Ignoring new segment because of format %i\n", format);
                return 1;
            }
            pos /= 100;
            if (stop > 0)
                stop /= 100;
            if (pin->pin.pin.pConnectedTo)
                IPin_NewSegment(pin->pin.pin.pConnectedTo, pos, stop, rate*applied_rate);
            return 1;
        }
        case GST_EVENT_EOS:
            if (pin->pin.pin.pConnectedTo)
                IPin_EndOfStream(pin->pin.pin.pConnectedTo);
            return 1;
        case GST_EVENT_FLUSH_START:
            if (pin->pin.pin.pConnectedTo)
                IPin_BeginFlush(pin->pin.pin.pConnectedTo);
            return 1;
        case GST_EVENT_FLUSH_STOP:
            if (pin->pin.pin.pConnectedTo)
                IPin_EndFlush(pin->pin.pin.pConnectedTo);
            return 1;
        default:
            FIXME("%p stub %s\n", event, gst_event_type_get_name(event->type));
            return gst_pad_event_default(pad, event);
    }
}

static void release_sample(void *data) {
    ULONG ret;
    ret = IMediaSample_Release((IMediaSample *)data);
    TRACE("Releasing %p returns %u\n", data, ret);
}

static HRESULT WINAPI GST_OutPin_QueryAccept(IPin *iface, const AM_MEDIA_TYPE *pmt) {
    GSTOutPin *pin = (GSTOutPin*)iface;
    FIXME("stub %p\n", pin);
    return S_OK;
}

static GstFlowReturn got_data_sink(GstPad *pad, GstBuffer *buf) {
    GSTOutPin *pin = gst_pad_get_element_private(pad);
    GSTImpl *This = (GSTImpl *)pin->pin.pin.pinInfo.pFilter;
    IMediaSample *sample;
    REFERENCE_TIME tStart, tStop;
    HRESULT hr;
    BOOL freeSamp = FALSE;

    if (This->initial) {
        gst_buffer_unref(buf);
        FIXME("Triggering %p %p\n", pad, pin->caps_event);
        SetEvent(pin->caps_event);
        return GST_FLOW_NOT_LINKED;
    }

    if (GST_IS_APP_BUFFER(buf)) {
        sample = GST_APP_BUFFER(buf)->priv;
        TRACE("Pushing buffer\n");
    } else if (buf->parent && GST_IS_APP_BUFFER(buf->parent)) {
        sample = GST_APP_BUFFER(buf->parent)->priv;
        TRACE("Pushing sub-buffer\n");
    } else {
        BYTE *ptr = NULL;
        hr = BaseOutputPinImpl_GetDeliveryBuffer(&pin->pin, &sample, NULL, NULL, 0);
        freeSamp = TRUE;
        if (hr == VFW_E_NOT_CONNECTED)
            return GST_FLOW_NOT_LINKED;
        if (FAILED(hr)) {
            ERR("Didn't get a GST_APP_BUFFER, and could not get a delivery buffer (%x), returning GST_FLOW_WRONG_STATE\n", hr);
            return GST_FLOW_WRONG_STATE;
        }
        FIXME("Did not get a GST_APP_BUFFER, creating a sample\n");
        IMediaSample_SetActualDataLength(sample, GST_BUFFER_SIZE(buf));
        IMediaSample_GetPointer(sample, &ptr);
        memcpy(ptr, GST_BUFFER_DATA(buf), GST_BUFFER_SIZE(buf));
    }

    if (GST_BUFFER_TIMESTAMP_IS_VALID(buf) &&
        GST_BUFFER_DURATION_IS_VALID(buf)) {
        tStart = buf->timestamp / 100;
        tStop = tStart + buf->duration / 100;
        IMediaSample_SetTime(sample, &tStart, &tStop);
    }
    else
        IMediaSample_SetTime(sample, NULL, NULL);

    IMediaSample_SetDiscontinuity(sample, GST_BUFFER_FLAG_IS_SET(buf, GST_BUFFER_FLAG_DISCONT));
    IMediaSample_SetPreroll(sample, GST_BUFFER_FLAG_IS_SET(buf, GST_BUFFER_FLAG_PREROLL));
    IMediaSample_SetSyncPoint(sample, !GST_BUFFER_FLAG_IS_SET(buf, GST_BUFFER_FLAG_DELTA_UNIT));

    if (!pin->pin.pin.pConnectedTo)
        hr = VFW_E_NOT_CONNECTED;
    else
        hr = IMemInputPin_Receive(pin->pin.pMemInputPin, sample);
    TRACE("sending sample: %08x\n", hr);
    gst_buffer_unref(buf);
    if (freeSamp)
        IMediaSample_Release(sample);
    if (hr == VFW_E_NOT_CONNECTED)
        return GST_FLOW_NOT_LINKED;
    else if (FAILED(hr))
        return GST_FLOW_WRONG_STATE;
    if (hr != S_OK)
        return GST_FLOW_RESEND;
    return GST_FLOW_OK;
}

static GstFlowReturn request_buffer_sink(GstPad *pad, guint64 ofs, guint size, GstCaps *caps, GstBuffer **buf) {
    GSTOutPin *pin = gst_pad_get_element_private(pad);
    GSTImpl *This = (GSTImpl *)pin->pin.pin.pinInfo.pFilter;
    IMediaSample *sample;
    BYTE *ptr;
    HRESULT hr;

    TRACE("Requesting buffer\n");
    if (This->initial) {
        int ret;
        ret = setcaps_sink(pad, caps);
        if (!ret)
            return GST_FLOW_NOT_NEGOTIATED;
        *buf = gst_buffer_new_and_alloc(size);
        return GST_FLOW_OK;
    }

    if (caps && caps != GST_PAD_CAPS(pad))
        if (!setcaps_sink(pad, caps))
            return GST_FLOW_NOT_NEGOTIATED;

    hr = BaseOutputPinImpl_GetDeliveryBuffer(&pin->pin, &sample, NULL, NULL, 0);
    if (hr == VFW_E_NOT_CONNECTED)
        return GST_FLOW_NOT_LINKED;
    if (FAILED(hr)) {
        ERR("Could not get output buffer: %08x\n", hr);
        *buf = NULL;
        return GST_FLOW_WRONG_STATE;
    }
    IMediaSample_SetActualDataLength(sample, size);
    IMediaSample_GetPointer(sample, &ptr);
    *buf = gst_app_buffer_new(ptr, size, release_sample, sample);
    if (!*buf) {
        IMediaSample_Release(sample);
        ERR("Out of memory\n");
        return GST_FLOW_ERROR;
    }
    gst_buffer_set_caps(*buf, caps);
    return GST_FLOW_OK;
}

static GstFlowReturn request_buffer_src(GstPad *pad, guint64 ofs, guint len, GstBuffer **buf) {
    GSTImpl *This = gst_pad_get_element_private(pad);
    int ret;

    *buf = NULL;
    TRACE("Requesting %s %u\n", wine_dbgstr_longlong(ofs), len);
    if (ofs == (guint64)-1)
        ofs = This->nextpullofs;
    if (ofs >= This->filesize) {
        WARN("Reading past eof: %s, %u\n", wine_dbgstr_longlong(ofs), len);
        return GST_FLOW_UNEXPECTED;
    }
    if (len + ofs > This->filesize)
        len = This->filesize - ofs;
    This->nextpullofs = ofs + len;

    ret = gst_pad_alloc_buffer(This->my_src, ofs, len, NULL, buf);
    if (ret >= 0) {
        HRESULT hr;
        hr = IAsyncReader_SyncRead(This->pInputPin.pReader, ofs, len, GST_BUFFER_DATA(*buf));
        if (FAILED(hr)) {
            ERR("Returned %08x\n", hr);
            return GST_FLOW_ERROR;
        }
    }
    return ret;
}

static void removed_decoded_pad(GstElement *bin, GstPad *pad, GSTImpl *This) {
    int x;
    GSTOutPin *pin;

    EnterCriticalSection(&This->filter.csFilter);
    for (x = 0; x < This->cStreams; ++x) {
        if (This->ppPins[x]->their_src == pad)
            break;
    }
    if (x == This->cStreams)
        goto out;
    pin = This->ppPins[x];
    gst_pad_unlink(pin->their_src, pin->my_sink);
    gst_object_unref(pin->their_src);
    pin->their_src = NULL;
out:
    TRACE("Removed %i/%i\n", x, This->cStreams);
    LeaveCriticalSection(&This->filter.csFilter);
}

static void init_new_decoded_pad(GstElement *bin, GstPad *pad, gboolean last, GSTImpl *This) {
    HRESULT hr;
    PIN_INFO piOutput;
    const char *typename;
    char *name;
    AM_MEDIA_TYPE amt = { };
    GstCaps *caps;
    GstStructure *arg;
    GstPad *mypad;
    GSTOutPin *pin;
    int ret;
    int isvid = 0, isaud = 0;

    piOutput.dir = PINDIR_OUTPUT;
    piOutput.pFilter = (IBaseFilter *)This;
    name = gst_pad_get_name(pad);
    MultiByteToWideChar(CP_UNIXCP, 0, name, -1, piOutput.achName, sizeof(piOutput.achName) / sizeof(piOutput.achName[0]) - 1);
    TRACE("Name: %s\n", name);
    g_free(name);
    piOutput.achName[sizeof(piOutput.achName) / sizeof(piOutput.achName[0]) - 1] = 0;

    caps = gst_pad_get_caps_reffed(pad);
    arg = gst_caps_get_structure(caps, 0);
    typename = gst_structure_get_name(arg);

    mypad = gst_pad_new(NULL, GST_PAD_SINK);
    gst_pad_set_chain_function(mypad, got_data_sink);
    gst_pad_set_event_function(mypad, event_sink);
    gst_pad_set_bufferalloc_function(mypad, request_buffer_sink);
    gst_pad_set_acceptcaps_function(mypad, accept_caps_sink);
    gst_pad_set_acceptcaps_function(mypad, setcaps_sink);

    if (!strcmp(typename, "audio/x-raw-int") ||
        !strcmp(typename, "audio/x-raw-float")) {
        isaud = 1;
    } else if (!strcmp(typename, "video/x-raw-rgb")
               || !strcmp(typename, "video/x-raw-yuv")) {
        isvid = 1;
    } else {
        FIXME("Unknown type \'%s\'\n", typename);
        return;
    }
    GST_PAD_CAPS(mypad) = GST_CAPS_ANY;
    hr = GST_AddPin(This, &piOutput, &amt);
    if (FAILED(hr)) {
        ERR("%08x\n", hr);
        return;
    }
    pin = This->ppPins[This->cStreams - 1];
    gst_pad_set_element_private(mypad, pin);
    pin->my_sink = mypad;
    pin->isaud = isaud;
    pin->isvid = isvid;

    ret = gst_pad_link(pad, mypad);
    gst_pad_activate_push(mypad, 1);
    FIXME("Linking: %i\n", ret);
    if (ret >= 0) {
        pin->their_src = pad;
        gst_object_ref(pin->their_src);
    }
}

static void existing_new_pad(GstElement *bin, GstPad *pad, gboolean last, GSTImpl *This) {
    int x;
    GstCaps *caps;
    GstStructure *arg;
    const char *typename, *ownname;
    caps = gst_pad_get_caps_reffed(pad);
    arg = gst_caps_get_structure(caps, 0);
    typename = gst_structure_get_name(arg);

    if (gst_pad_is_linked(pad))
        return;

    /* Still holding our own lock */
    if (This->initial) {
        init_new_decoded_pad(bin, pad, last, This);
        return;
    }

    EnterCriticalSection(&This->filter.csFilter);
    for (x = 0; x < This->cStreams; ++x) {
        GSTOutPin *pin = This->ppPins[x];
        if (!pin->their_src) {
            caps = gst_pad_get_caps_reffed(pin->my_sink);
            arg = gst_caps_get_structure(caps, 0);
            ownname = gst_structure_get_name(arg);
            if (!strcmp(typename, ownname) && gst_pad_link(pad, pin->my_sink) >= 0) {
                pin->their_src = pad;
                gst_object_ref(pin->their_src);
                TRACE("Relinked\n");
                LeaveCriticalSection(&This->filter.csFilter);
                return;
            }
        }
    }
    init_new_decoded_pad(bin, pad, last, This);
    LeaveCriticalSection(&This->filter.csFilter);
}

static gboolean check_get_range(GstPad *pad) {
    return 1;
}

static gboolean query_function(GstPad *pad, GstQuery *query) {
    GSTImpl *This = gst_pad_get_element_private(pad);
    GstFormat format;
    int ret;
    LONGLONG duration;

    switch (GST_QUERY_TYPE(query)) {
        case GST_QUERY_DURATION:
            gst_query_parse_duration (query, &format, NULL);
            if (format == GST_FORMAT_PERCENT) {
                gst_query_set_duration (query, GST_FORMAT_PERCENT, GST_FORMAT_PERCENT_MAX);
                return 1;
            }
            ret = gst_pad_query_convert (pad, GST_FORMAT_BYTES, This->filesize, &format, &duration);
            gst_query_set_duration(query, format, duration);
            return ret;
        case GST_QUERY_SEEKING:
            gst_query_parse_seeking (query, &format, NULL, NULL, NULL);
            TRACE("Seeking %i %i\n", format, GST_FORMAT_BYTES);
            if (format != GST_FORMAT_BYTES)
                return 0;
            gst_query_set_seeking(query, GST_FORMAT_BYTES, 1, 0, This->filesize);
            return 1;
        default:
            FIXME("Unhandled query type %i\n", GST_QUERY_TYPE(query));
        case GST_QUERY_URI:
            return 1;
    }
}

static void no_more_pads(GstElement *decodebin, GSTImpl *This) {
    FIXME("Done\n");
    SetEvent(This->event);
}

typedef enum {
  GST_AUTOPLUG_SELECT_TRY,
  GST_AUTOPLUG_SELECT_EXPOSE,
  GST_AUTOPLUG_SELECT_SKIP
} GstAutoplugSelectResult;

static GstAutoplugSelectResult autoplug_blacklist(GstElement *bin, GstPad *pad, GstCaps *caps, GstElementFactory *fact, GSTImpl *This) {
    const char *name = gst_element_factory_get_longname(fact);

    if (strstr(name, "Player protection")) {
        WARN("Blacklisted a/52 decoder because it only works in Totem\n");
        return GST_AUTOPLUG_SELECT_SKIP;
    }
    if (!strcmp(name, "Fluendo Hardware Accelerated Video Decoder")) {
        WARN("Disabled video acceleration since it breaks in wine\n");
        return GST_AUTOPLUG_SELECT_SKIP;
    }
    TRACE("using \"%s\"\n", name);
    return GST_AUTOPLUG_SELECT_TRY;
}

static HRESULT GST_Connect(GSTInPin *pPin, IPin *pConnectPin, ALLOCATOR_PROPERTIES *props) {
    GSTImpl *This = (GSTImpl*)pPin->pin.pinInfo.pFilter;
    HRESULT hr;
    int ret, i;
    LONGLONG avail;
    GstFormat format = GST_FORMAT_TIME;
    GstStaticPadTemplate src_template = GST_STATIC_PAD_TEMPLATE(
        "quartz_src",
        GST_PAD_SRC,
        GST_PAD_ALWAYS,
        GST_STATIC_CAPS_ANY);

    TRACE("%p %p %p\n", pPin, pConnectPin, props);
    This->props = *props;
    IAsyncReader_Length(pPin->pReader, &This->filesize, &avail);

    This->gstfilter = gst_element_factory_make("decodebin2", NULL);
    if (!This->gstfilter) {
        FIXME("Could not make source filter, are gstreamer-plugins-* installed?\n");
        return E_FAIL;
    }
    g_signal_connect(This->gstfilter, "new-decoded-pad", G_CALLBACK(existing_new_pad), This);
    g_signal_connect(This->gstfilter, "pad-removed", G_CALLBACK(removed_decoded_pad), This);
    g_signal_connect(This->gstfilter, "autoplug-select", G_CALLBACK(autoplug_blacklist), This);

    This->my_src = gst_pad_new_from_static_template(&src_template, "quartz-src");
    gst_pad_set_getrange_function(This->my_src, request_buffer_src);
    gst_pad_set_checkgetrange_function(This->my_src, check_get_range);
    gst_pad_set_query_function(This->my_src, query_function);
    gst_pad_set_event_function(This->my_src, event_src);
    gst_pad_set_element_private (This->my_src, This);
    This->their_sink = gst_element_get_static_pad(This->gstfilter, "sink");

    g_signal_connect(This->gstfilter, "no-more-pads", G_CALLBACK(no_more_pads), This);
    ret = gst_pad_link(This->my_src, This->their_sink);
    gst_object_unref(This->their_sink);
    if (ret < 0) {
        ERR("Returns: %i\n", ret);
        return E_FAIL;
    }
    This->start = This->nextofs = This->nextpullofs = 0;
    This->stop = This->filesize;

    /* Add initial pins */
    This->initial = This->discont = 1;
    gst_element_set_state(This->gstfilter, GST_STATE_PLAYING);
    gst_pad_set_active(This->my_src, 1);
    WaitForSingleObject(This->event, -1);
    gst_element_get_state(This->gstfilter, NULL, NULL, -1);

    if (ret < 0) {
        WARN("Ret: %i\n", ret);
        hr = E_FAIL;
    } else if (!This->cStreams) {
        FIXME("Gstreamer could not find any streams\n");
        hr = E_FAIL;
    } else {
        for (i = 0; i < This->cStreams; ++i)
            WaitForSingleObject(This->ppPins[i]->caps_event, -1);
        hr = S_OK;
    }
    *props = This->props;
    gst_pad_query_duration(This->ppPins[0]->their_src, &format, &This->sourceSeeking.llDuration);
    This->sourceSeeking.llDuration /= 100;
    gst_element_set_state(This->gstfilter, GST_STATE_READY);
    gst_element_get_state(This->gstfilter, NULL, NULL, -1);

    This->initial = 0;
    This->nextofs = This->nextpullofs = 0;

    GST_ChangeCurrent((IMediaSeeking*)&This->sourceSeeking);

    This->sourceSeeking.llCurrent = 0;
    This->sourceSeeking.llStop = This->sourceSeeking.llDuration;
    return hr;
}

static inline GSTImpl *impl_from_IMediaSeeking( IMediaSeeking *iface ) {
    return (GSTImpl *)((char*)iface - FIELD_OFFSET(GSTImpl, sourceSeeking.lpVtbl));
}

static IPin* WINAPI GST_GetPin(BaseFilter *iface, int pos)
{
    GSTImpl *This = (GSTImpl *)iface;
    TRACE("Asking for pos %x\n", pos);

    if (pos > This->cStreams || pos < 0)
        return NULL;
    if (!pos)
    {
        IPin_AddRef((IPin*)&This->pInputPin);
        return (IPin*)&This->pInputPin;
    }
    else
    {
        IPin_AddRef((IPin*)This->ppPins[pos - 1]);
        return (IPin*)This->ppPins[pos - 1];
    }
}

static LONG WINAPI GST_GetPinCount(BaseFilter *iface)
{
    GSTImpl *This = (GSTImpl *)iface;
    return (This->cStreams + 1);
}

static const BaseFilterFuncTable BaseFuncTable = {
    GST_GetPin,
    GST_GetPinCount
};

IUnknown * CALLBACK Gstreamer_Splitter_create(IUnknown *punkout, HRESULT *phr) {
    IUnknown *obj = NULL;
    PIN_INFO *piInput;
    GSTImpl *This;

    if (!Gstreamer_init())
    {
        *phr = E_FAIL;
        return NULL;
    }

    This = CoTaskMemAlloc(sizeof(*This));
    obj = (IUnknown*)This;
    if (!This)
    {
        *phr = E_OUTOFMEMORY;
        return NULL;
    }

    BaseFilter_Init(&This->filter, &GST_Vtbl, &CLSID_Gstreamer_Splitter, (DWORD_PTR)(__FILE__ ": GSTImpl.csFilter"), &BaseFuncTable);

    This->cStreams = 0;
    This->ppPins = NULL;
    This->event = CreateEventW(NULL, 0, 0, NULL);

    SourceSeeking_Init(&This->sourceSeeking, &GST_Seeking_Vtbl, GST_ChangeStop, GST_ChangeCurrent, GST_ChangeRate, &This->filter.csFilter);

    piInput = &This->pInputPin.pin.pinInfo;
    piInput->dir = PINDIR_INPUT;
    piInput->pFilter = (IBaseFilter *)This;
    lstrcpynW(piInput->achName, wcsInputPinName, sizeof(piInput->achName) / sizeof(piInput->achName[0]));
    This->pInputPin.pin.lpVtbl = &GST_InputPin_Vtbl;
    This->pInputPin.pin.refCount = 1;
    This->pInputPin.pin.pConnectedTo = NULL;
    This->pInputPin.pin.pCritSec = &This->filter.csFilter;
    ZeroMemory(&This->pInputPin.pin.mtCurrent, sizeof(AM_MEDIA_TYPE));
    *phr = S_OK;
    return obj;
}

static void GST_Destroy(GSTImpl *This) {
    IPin *connected = NULL;
    ULONG pinref;

    TRACE("Destroying\n");

    CloseHandle(This->event);

    /* Don't need to clean up output pins, disconnecting input pin will do that */
    IPin_ConnectedTo((IPin *)&This->pInputPin, &connected);
    if (connected) {
        assert(IPin_Disconnect(connected) == S_OK);
        IPin_Release(connected);
        assert(IPin_Disconnect((IPin *)&This->pInputPin) == S_OK);
    }
    pinref = IPin_Release((IPin *)&This->pInputPin);
    if (pinref) {
        /* Valgrind could find this, if I kill it here */
        ERR("pinref should be null, is %u, destroying anyway\n", pinref);
        assert((LONG)pinref > 0);

        while (pinref)
            pinref = IPin_Release((IPin *)&This->pInputPin);
    }
    CoTaskMemFree(This);
}

static HRESULT WINAPI GST_QueryInterface(IBaseFilter *iface, REFIID riid, LPVOID *ppv) {
    GSTImpl *This = (GSTImpl *)iface;
    TRACE("(%s, %p)\n", debugstr_guid(riid), ppv);

    *ppv = NULL;

    if (IsEqualIID(riid, &IID_IUnknown))
        *ppv = This;
    else if (IsEqualIID(riid, &IID_IPersist))
        *ppv = This;
    else if (IsEqualIID(riid, &IID_IMediaFilter))
        *ppv = This;
    else if (IsEqualIID(riid, &IID_IBaseFilter))
        *ppv = This;
    else if (IsEqualIID(riid, &IID_IMediaSeeking))
        *ppv = &This->sourceSeeking;

    if (*ppv) {
        IUnknown_AddRef((IUnknown *)(*ppv));
        return S_OK;
    }

    if (!IsEqualIID(riid, &IID_IPin) && !IsEqualIID(riid, &IID_IVideoWindow))
        FIXME("No interface for %s!\n", debugstr_guid(riid));

    return E_NOINTERFACE;
}

static ULONG WINAPI GST_Release(IBaseFilter *iface) {
    GSTImpl *This = (GSTImpl *)iface;
    ULONG refCount = BaseFilterImpl_Release(iface);

    TRACE("(%p)->() Release from %d\n", This, refCount + 1);

    if (!refCount)
        GST_Destroy(This);

    return refCount;
}

static HRESULT WINAPI GST_Stop(IBaseFilter *iface) {
    GSTImpl *This = (GSTImpl *)iface;

    TRACE("()\n");

    if (This->gstfilter) {
        IAsyncReader_BeginFlush(This->pInputPin.pReader);
        gst_element_set_state(This->gstfilter, GST_STATE_READY);
        IAsyncReader_EndFlush(This->pInputPin.pReader);
    }
    return S_OK;
}

static HRESULT WINAPI GST_Pause(IBaseFilter *iface) {
    HRESULT hr = S_OK;
    GSTImpl *This = (GSTImpl *)iface;
    GstState now;
    GstStateChangeReturn ret;
    TRACE("()\n");

    if (!This->gstfilter)
        return VFW_E_NOT_CONNECTED;

    gst_element_get_state(This->gstfilter, &now, NULL, -1);
    if (now == GST_STATE_PAUSED)
        return S_OK;
    if (now != GST_STATE_PLAYING)
        hr = IBaseFilter_Run(iface, -1);
    if (FAILED(hr))
        return hr;
    ret = gst_element_set_state(This->gstfilter, GST_STATE_PAUSED);
    if (ret == GST_STATE_CHANGE_ASYNC)
        hr = S_FALSE;
    return hr;
}

static HRESULT WINAPI GST_Run(IBaseFilter *iface, REFERENCE_TIME tStart) {
    HRESULT hr = S_OK;
    GSTImpl *This = (GSTImpl *)iface;
    ULONG i;
    GstState now;
    HRESULT hr_any = VFW_E_NOT_CONNECTED;

    TRACE("(%s)\n", wine_dbgstr_longlong(tStart));

    if (!This->gstfilter)
        return VFW_E_NOT_CONNECTED;

    gst_element_get_state(This->gstfilter, &now, NULL, -1);
    if (now == GST_STATE_PLAYING)
        return S_OK;
    if (now == GST_STATE_PAUSED) {
        GstStateChangeReturn ret;
        ret = gst_element_set_state(This->gstfilter, GST_STATE_PAUSED);
        if (ret == GST_STATE_CHANGE_ASYNC)
            return S_FALSE;
        return S_OK;
    }

    EnterCriticalSection(&This->filter.csFilter);
    gst_pad_set_blocked(This->my_src, 0);
    gst_pad_set_blocked(This->their_sink, 0);
    gst_element_set_state(This->gstfilter, GST_STATE_PLAYING);
    This->filter.rtStreamStart = tStart;

    for (i = 0; i < This->cStreams; i++) {
        hr = BaseOutputPinImpl_Active((BaseOutputPin *)This->ppPins[i]);
        if (SUCCEEDED(hr)) {
            gst_pad_set_blocked(This->ppPins[i]->my_sink, 0);
            if (This->ppPins[i]->their_src)
                gst_pad_set_blocked(This->ppPins[i]->their_src, 0);
            hr_any = hr;
        }
    }
    hr = hr_any;
    if (SUCCEEDED(hr))
        gst_pad_set_active(This->my_src, 1);
    LeaveCriticalSection(&This->filter.csFilter);

    return hr;
}

static HRESULT WINAPI GST_GetState(IBaseFilter *iface, DWORD dwMilliSecsTimeout, FILTER_STATE *pState) {
    GSTImpl *This = (GSTImpl *)iface;
    HRESULT hr = S_OK;
    GstState now, pending;
    GstStateChangeReturn ret;

    TRACE("(%d, %p)\n", dwMilliSecsTimeout, pState);

    if (!This->gstfilter) {
        pState = State_Stopped;
        return S_OK;
    }

    ret = gst_element_get_state(This->gstfilter, &now, &pending, dwMilliSecsTimeout == INFINITE ? -1 : dwMilliSecsTimeout * 1000);

    if (ret == GST_STATE_CHANGE_ASYNC)
        hr = VFW_S_STATE_INTERMEDIATE;
    else
        pending = now;

    switch (pending) {
        case GST_STATE_PAUSED: *pState = State_Paused; return hr;
        case GST_STATE_PLAYING: *pState = State_Running; return hr;
        default: *pState = State_Stopped; return hr;
    }
}

static HRESULT WINAPI GST_FindPin(IBaseFilter *iface, LPCWSTR Id, IPin **ppPin) {
    FIXME("(%p)->(%s,%p) stub\n", iface, debugstr_w(Id), ppPin);
    return E_NOTIMPL;
}

static const IBaseFilterVtbl GST_Vtbl = {
    GST_QueryInterface,
    BaseFilterImpl_AddRef,
    GST_Release,
    BaseFilterImpl_GetClassID,
    GST_Stop,
    GST_Pause,
    GST_Run,
    GST_GetState,
    BaseFilterImpl_SetSyncSource,
    BaseFilterImpl_GetSyncSource,
    BaseFilterImpl_EnumPins,
    GST_FindPin,
    BaseFilterImpl_QueryFilterInfo,
    BaseFilterImpl_JoinFilterGraph,
    BaseFilterImpl_QueryVendorInfo
};

static HRESULT WINAPI GST_ChangeCurrent(IMediaSeeking *iface) {
    GSTImpl *This = impl_from_IMediaSeeking(iface);
    int i;
    GstEvent *ev = gst_event_new_seek(This->sourceSeeking.dRate, GST_FORMAT_TIME, GST_SEEK_FLAG_FLUSH, GST_SEEK_TYPE_SET, This->sourceSeeking.llCurrent * 100, GST_SEEK_TYPE_NONE, -1);
    FIXME("(%p) filter hasn't implemented current position change, going to %i.%i!\n", iface, (int)(This->sourceSeeking.llCurrent / 10000000), (int)((This->sourceSeeking.llCurrent / 10000)%1000));
    for (i = 0; i < This->cStreams; ++i) {
        GstPad *pad = This->ppPins[i]->my_sink;
        gst_event_ref(ev);
        gst_pad_push_event(pad, ev);
    }
    gst_event_unref(ev);
    return S_OK;
}

static HRESULT WINAPI GST_ChangeStop(IMediaSeeking *iface) {
    GSTImpl *This = impl_from_IMediaSeeking(iface);
    int i;
    GstEvent *ev = gst_event_new_seek(This->sourceSeeking.dRate, GST_FORMAT_TIME, GST_SEEK_FLAG_FLUSH, GST_SEEK_TYPE_NONE, -1, GST_SEEK_TYPE_SET, This->sourceSeeking.llStop * 100);
    FIXME("(%p) filter hasn't implemented stop position change, going to %i.%i!\n", iface, (int)(This->sourceSeeking.llStop / 10000000), (int)((This->sourceSeeking.llStop / 10000)%1000));
    for (i = 0; i < This->cStreams; ++i) {
        GstPad *pad = This->ppPins[i]->my_sink;
        gst_event_ref(ev);
        gst_pad_push_event(pad, ev);
    }
    gst_event_unref(ev);
    return S_OK;
}

static HRESULT WINAPI GST_ChangeRate(IMediaSeeking *iface) {
    GSTImpl *This = impl_from_IMediaSeeking(iface);
    int i;
    GstEvent *ev = gst_event_new_seek(This->sourceSeeking.dRate, GST_FORMAT_TIME, GST_SEEK_FLAG_FLUSH, GST_SEEK_TYPE_NONE, -1, GST_SEEK_TYPE_NONE, -1);
    FIXME("(%p) filter hasn't implemented rate change! Going to %g\n", iface, This->sourceSeeking.dRate);
    for (i = 0; i < This->cStreams; ++i) {
        GstPad *pad = This->ppPins[i]->my_sink;
        gst_event_ref(ev);
        gst_pad_push_event(pad, ev);
    }
    gst_event_unref(ev);
    return S_OK;
}

static HRESULT WINAPI GST_Seeking_QueryInterface(IMediaSeeking *iface, REFIID riid, void **ppv) {
    GSTImpl *This = impl_from_IMediaSeeking(iface);
    return IUnknown_QueryInterface((IUnknown *)This, riid, ppv);
}

static ULONG WINAPI GST_Seeking_AddRef(IMediaSeeking *iface) {
    GSTImpl *This = impl_from_IMediaSeeking(iface);
    return IUnknown_AddRef((IUnknown *)This);
}

static ULONG WINAPI GST_Seeking_Release(IMediaSeeking *iface) {
    GSTImpl *This = impl_from_IMediaSeeking(iface);
    return IUnknown_Release((IUnknown *)This);
}

static const IMediaSeekingVtbl GST_Seeking_Vtbl =
{
    GST_Seeking_QueryInterface,
    GST_Seeking_AddRef,
    GST_Seeking_Release,
    SourceSeekingImpl_GetCapabilities,
    SourceSeekingImpl_CheckCapabilities,
    SourceSeekingImpl_IsFormatSupported,
    SourceSeekingImpl_QueryPreferredFormat,
    SourceSeekingImpl_GetTimeFormat,
    SourceSeekingImpl_IsUsingTimeFormat,
    SourceSeekingImpl_SetTimeFormat,
    SourceSeekingImpl_GetDuration,
    SourceSeekingImpl_GetStopPosition,
    SourceSeekingImpl_GetCurrentPosition,
    SourceSeekingImpl_ConvertTimeFormat,
    SourceSeekingImpl_SetPositions,
    SourceSeekingImpl_GetPositions,
    SourceSeekingImpl_GetAvailable,
    SourceSeekingImpl_SetRate,
    SourceSeekingImpl_GetRate,
    SourceSeekingImpl_GetPreroll
};

static HRESULT WINAPI GSTOutPin_QueryInterface(IPin *iface, REFIID riid, void **ppv) {
    GSTOutPin *This = (GSTOutPin *)iface;

    TRACE("(%s, %p)\n", debugstr_guid(riid), ppv);

    *ppv = NULL;

    if (IsEqualIID(riid, &IID_IUnknown))
        *ppv = iface;
    else if (IsEqualIID(riid, &IID_IPin))
        *ppv = iface;
    else if (IsEqualIID(riid, &IID_IMediaSeeking))
        return IBaseFilter_QueryInterface(This->pin.pin.pinInfo.pFilter, &IID_IMediaSeeking, ppv);

    if (*ppv) {
        IUnknown_AddRef((IUnknown *)(*ppv));
        return S_OK;
    }
    FIXME("No interface for %s!\n", debugstr_guid(riid));
    return E_NOINTERFACE;
}

static ULONG WINAPI GSTOutPin_Release(IPin *iface) {
    GSTOutPin *This = (GSTOutPin *)iface;
    ULONG refCount = InterlockedDecrement(&This->pin.pin.refCount);
    TRACE("(%p)->() Release from %d\n", iface, refCount + 1);

    if (!refCount) {
        if (This->their_src)
            gst_pad_unlink(This->their_src, This->my_sink);
        gst_object_unref(This->my_sink);
        CloseHandle(This->caps_event);
        DeleteMediaType(This->pmt);
        FreeMediaType(&This->pin.pin.mtCurrent);
        CoTaskMemFree(This);
        return 0;
    }
    return refCount;
}

static HRESULT WINAPI GSTOutPin_GetMediaType(BasePin *iface, int iPosition, AM_MEDIA_TYPE *pmt)
{
    GSTOutPin *This = (GSTOutPin *)iface;

    if (iPosition < 0)
        return E_INVALIDARG;
    if (iPosition > 0)
        return VFW_S_NO_MORE_ITEMS;
    CopyMediaType(pmt, This->pmt);
    return S_OK;
}

static HRESULT WINAPI GSTOutPin_DecideBufferSize(BaseOutputPin *iface, IMemAllocator *pAlloc, ALLOCATOR_PROPERTIES *ppropInputRequest)
{
    /* Unused */
    return S_OK;
}

static HRESULT WINAPI GSTOutPin_DecideAllocator(BaseOutputPin *iface, IMemInputPin *pPin, IMemAllocator **pAlloc)
{
    HRESULT hr;
    GSTOutPin *This = (GSTOutPin *)iface;
    GSTImpl *GSTfilter = (GSTImpl*)This->pin.pin.pinInfo.pFilter;

    pAlloc = NULL;
    if (GSTfilter->pInputPin.pAlloc)
        hr = IMemInputPin_NotifyAllocator(pPin, GSTfilter->pInputPin.pAlloc, FALSE);
    else
        hr = VFW_E_NO_ALLOCATOR;

    return hr;
}

static HRESULT WINAPI GSTOutPin_BreakConnect(BaseOutputPin *This)
{
    HRESULT hr;

    TRACE("(%p)->()\n", This);

    EnterCriticalSection(This->pin.pCritSec);
    if (!This->pin.pConnectedTo || !This->pMemInputPin)
        hr = VFW_E_NOT_CONNECTED;
    else
    {
        hr = IPin_Disconnect(This->pin.pConnectedTo);
        IPin_Disconnect((IPin *)This);
    }
    LeaveCriticalSection(This->pin.pCritSec);

    return hr;
}

static const IPinVtbl GST_OutputPin_Vtbl = {
    GSTOutPin_QueryInterface,
    BasePinImpl_AddRef,
    GSTOutPin_Release,
    BaseOutputPinImpl_Connect,
    BaseOutputPinImpl_ReceiveConnection,
    BaseOutputPinImpl_Disconnect,
    BasePinImpl_ConnectedTo,
    BasePinImpl_ConnectionMediaType,
    BasePinImpl_QueryPinInfo,
    BasePinImpl_QueryDirection,
    BasePinImpl_QueryId,
    GST_OutPin_QueryAccept,
    BasePinImpl_EnumMediaTypes,
    BasePinImpl_QueryInternalConnections,
    BaseOutputPinImpl_EndOfStream,
    BaseOutputPinImpl_BeginFlush,
    BaseOutputPinImpl_EndFlush,
    BaseOutputPinImpl_NewSegment
};

static const BasePinFuncTable output_BaseFuncTable = {
    NULL,
    BaseOutputPinImpl_AttemptConnection,
    BasePinImpl_GetMediaTypeVersion,
    GSTOutPin_GetMediaType
};

static const BaseOutputPinFuncTable output_BaseOutputFuncTable = {
    GSTOutPin_DecideBufferSize,
    GSTOutPin_DecideAllocator,
    GSTOutPin_BreakConnect
};

static HRESULT GST_AddPin(GSTImpl *This, const PIN_INFO *piOutput, const AM_MEDIA_TYPE *amt) {
    HRESULT hr;
    This->ppPins = CoTaskMemRealloc(This->ppPins, (This->cStreams + 1) * sizeof(IPin *));

    hr = BaseOutputPin_Construct(&GST_OutputPin_Vtbl, sizeof(GSTOutPin), piOutput, &output_BaseFuncTable, &output_BaseOutputFuncTable, &This->filter.csFilter, (IPin**)(This->ppPins + This->cStreams));
    if (SUCCEEDED(hr)) {
        GSTOutPin *pin = This->ppPins[This->cStreams];
        pin->pmt = CoTaskMemAlloc(sizeof(AM_MEDIA_TYPE));
        CopyMediaType(pin->pmt, amt);
        pin->pin.pin.pinInfo.pFilter = (LPVOID)This;
        pin->caps_event = CreateEventW(NULL, 0, 0, NULL);
        This->cStreams++;
        BaseFilterImpl_IncrementPinVersion((BaseFilter*)This);
    } else
        ERR("Failed with error %x\n", hr);
    return hr;
}

static HRESULT GST_RemoveOutputPins(GSTImpl *This) {
    HRESULT hr;
    ULONG i;
    GSTOutPin **ppOldPins = This->ppPins;
    TRACE("(%p)\n", This);

    gst_element_set_state(This->gstfilter, GST_STATE_NULL);
    gst_pad_unlink(This->my_src, This->their_sink);
    This->my_src = This->their_sink = NULL;

    for (i = 0; i < This->cStreams; i++) {
        hr = BaseOutputPinImpl_BreakConnect(&ppOldPins[i]->pin);
        TRACE("Disconnect: %08x\n", hr);
        IPin_Release((IPin*)ppOldPins[i]);
    }
    This->cStreams = 0;
    This->ppPins = NULL;
    gst_object_unref(This->gstfilter);
    This->gstfilter = NULL;
    BaseFilterImpl_IncrementPinVersion((BaseFilter*)This);
    CoTaskMemFree(ppOldPins);
    return S_OK;
}

static ULONG WINAPI GSTInPin_Release(IPin *iface) {
    GSTInPin *This = (GSTInPin*)iface;
    ULONG refCount = InterlockedDecrement(&This->pin.refCount);

    TRACE("(%p)->() Release from %d\n", iface, refCount + 1);
    if (!refCount) {
        FreeMediaType(&This->pin.mtCurrent);
        if (This->pAlloc)
            IMemAllocator_Release(This->pAlloc);
        This->pAlloc = NULL;
        This->pin.lpVtbl = NULL;
        return 0;
    } else
        return refCount;
}

static HRESULT WINAPI GSTInPin_ReceiveConnection(IPin *iface, IPin *pReceivePin, const AM_MEDIA_TYPE *pmt) {
    PIN_DIRECTION pindirReceive;
    HRESULT hr = S_OK;
    GSTInPin *This = (GSTInPin*)iface;

    TRACE("(%p/%p)->(%p, %p)\n", This, iface, pReceivePin, pmt);
    dump_AM_MEDIA_TYPE(pmt);

    EnterCriticalSection(This->pin.pCritSec);
    if (!This->pin.pConnectedTo) {
        ALLOCATOR_PROPERTIES props;

        props.cBuffers = 4;
        props.cbBuffer = 16384;
        props.cbAlign = 1;
        props.cbPrefix = 0;

        if (SUCCEEDED(hr) && IPin_QueryAccept(iface, pmt) != S_OK)
            hr = VFW_E_TYPE_NOT_ACCEPTED;
        if (SUCCEEDED(hr)) {
            IPin_QueryDirection(pReceivePin, &pindirReceive);
            if (pindirReceive != PINDIR_OUTPUT) {
                ERR("Can't connect from non-output pin\n");
                hr = VFW_E_INVALID_DIRECTION;
            }
        }

        This->pReader = NULL;
        This->pAlloc = NULL;
        if (SUCCEEDED(hr))
            hr = IPin_QueryInterface(pReceivePin, &IID_IAsyncReader, (LPVOID *)&This->pReader);
        if (SUCCEEDED(hr))
            hr = GST_Connect(This, pReceivePin, &props);
        if (SUCCEEDED(hr))
            hr = IAsyncReader_RequestAllocator(This->pReader, NULL, &props, &This->pAlloc);
        if (SUCCEEDED(hr)) {
            CopyMediaType(&This->pin.mtCurrent, pmt);
            This->pin.pConnectedTo = pReceivePin;
            IPin_AddRef(pReceivePin);
            hr = IMemAllocator_Commit(This->pAlloc);
        } else {
            GST_RemoveOutputPins((GSTImpl *)This->pin.pinInfo.pFilter);
            if (This->pReader)
                IAsyncReader_Release(This->pReader);
            This->pReader = NULL;
            if (This->pAlloc)
                IMemAllocator_Release(This->pAlloc);
            This->pAlloc = NULL;
        }
        TRACE("Size: %i\n", props.cbBuffer);
    } else
        hr = VFW_E_ALREADY_CONNECTED;
    LeaveCriticalSection(This->pin.pCritSec);
    return hr;
}

static HRESULT WINAPI GSTInPin_Disconnect(IPin *iface) {
    HRESULT hr;
    GSTInPin *This = (GSTInPin*)iface;
    FILTER_STATE state;
    TRACE("()\n");

    hr = IBaseFilter_GetState(This->pin.pinInfo.pFilter, INFINITE, &state);
    EnterCriticalSection(This->pin.pCritSec);
    if (This->pin.pConnectedTo) {
        GSTImpl *Parser = (GSTImpl *)This->pin.pinInfo.pFilter;

        if (SUCCEEDED(hr) && state == State_Stopped) {
            IMemAllocator_Decommit(This->pAlloc);
            IPin_Disconnect(This->pin.pConnectedTo);
            This->pin.pConnectedTo = NULL;
            hr = GST_RemoveOutputPins(Parser);
        } else
            hr = VFW_E_NOT_STOPPED;
    } else
        hr = S_FALSE;
    LeaveCriticalSection(This->pin.pCritSec);
    return hr;
}

static HRESULT WINAPI GSTInPin_QueryAccept(IPin *iface, const AM_MEDIA_TYPE *pmt) {
    GSTInPin *This = (GSTInPin*)iface;

    TRACE("(%p)->(%p)\n", This, pmt);
    dump_AM_MEDIA_TYPE(pmt);

    if (IsEqualIID(&pmt->majortype, &MEDIATYPE_Stream))
        return S_OK;
    return S_FALSE;
}

static HRESULT WINAPI GSTInPin_EndOfStream(IPin *iface) {
    GSTInPin *pin = (GSTInPin*)iface;
    GSTImpl *This = (GSTImpl*)pin->pin.pinInfo.pFilter;

    FIXME("Propagate message on %p\n", This);
    return S_OK;
}

static HRESULT WINAPI GSTInPin_BeginFlush(IPin *iface) {
    GSTInPin *pin = (GSTInPin*)iface;
    GSTImpl *This = (GSTImpl*)pin->pin.pinInfo.pFilter;

    FIXME("Propagate message on %p\n", This);
    return S_OK;
}

static HRESULT WINAPI GSTInPin_EndFlush(IPin *iface) {
    GSTInPin *pin = (GSTInPin*)iface;
    GSTImpl *This = (GSTImpl*)pin->pin.pinInfo.pFilter;

    FIXME("Propagate message on %p\n", This);
    return S_OK;
}

static HRESULT WINAPI GSTInPin_NewSegment(IPin *iface, REFERENCE_TIME tStart, REFERENCE_TIME tStop, double dRate) {
    GSTInPin *pin = (GSTInPin*)iface;
    GSTImpl *This = (GSTImpl*)pin->pin.pinInfo.pFilter;

    FIXME("Propagate message on %p\n", This);
    return S_OK;
}

static HRESULT WINAPI GSTInPin_QueryInterface(IPin * iface, REFIID riid, LPVOID * ppv)
{
    GSTInPin *This = (GSTInPin*)iface;

    TRACE("(%p/%p)->(%s, %p)\n", This, iface, debugstr_guid(riid), ppv);

    *ppv = NULL;

    if (IsEqualIID(riid, &IID_IUnknown))
        *ppv = iface;
    else if (IsEqualIID(riid, &IID_IPin))
        *ppv = iface;
    else if (IsEqualIID(riid, &IID_IMediaSeeking))
    {
        return IBaseFilter_QueryInterface(This->pin.pinInfo.pFilter, &IID_IMediaSeeking, ppv);
    }

    if (*ppv)
    {
        IUnknown_AddRef((IUnknown *)(*ppv));
        return S_OK;
    }

    FIXME("No interface for %s!\n", debugstr_guid(riid));

    return E_NOINTERFACE;
}

static const IPinVtbl GST_InputPin_Vtbl = {
    GSTInPin_QueryInterface,
    BasePinImpl_AddRef,
    GSTInPin_Release,
    BaseInputPinImpl_Connect,
    GSTInPin_ReceiveConnection,
    GSTInPin_Disconnect,
    BasePinImpl_ConnectedTo,
    BasePinImpl_ConnectionMediaType,
    BasePinImpl_QueryPinInfo,
    BasePinImpl_QueryDirection,
    BasePinImpl_QueryId,
    GSTInPin_QueryAccept,
    BasePinImpl_EnumMediaTypes,
    BasePinImpl_QueryInternalConnections,
    GSTInPin_EndOfStream,
    GSTInPin_BeginFlush,
    GSTInPin_EndFlush,
    GSTInPin_NewSegment
};
