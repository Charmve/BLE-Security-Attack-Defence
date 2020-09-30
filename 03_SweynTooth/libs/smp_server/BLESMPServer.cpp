
#include <Python.h>
#include <stdio.h>
#include <stdlib.h>
#include <algorithm>
#include <queue>
#include <string>

extern "C"
{
#include "bthost.h"
#include "bluetooth.h"
}

#define MODULE_NAME "BLESMPServer"
#define MODULE_DESCRIPTION "A SMP Server module\nPackets received are answered according to bluetooth SMP specification\nBlueZ linux implementation is used"

static PyObject *PythonError;
struct bthost *blehost;
std::queue<struct PACKET> packets_queue;

extern int force_local_key_distribution;
extern uint8_t ltk[16];

struct PACKET
{
    uint8_t buf[1024];
    uint8_t len = 0;
};

void ReverseBytes(uint8_t *start, int size)
{
    uint8_t *istart = start, *iend = istart + size;
    std::reverse(istart, iend);
}

static PyObject *send_hci(PyObject *self, PyObject *args)
{
    Py_buffer str;
    PyObject *packet_list;
    uint32_t size;

    if (!PyArg_ParseTuple(args, "s*", &str))
    {
        return NULL;
    }

    bthost_receive_h4(blehost, str.buf, str.len);

    PyBuffer_Release(&str);

    size = packets_queue.size();
    if (size)
    {
        packet_list = PyList_New(size);
        for (Py_ssize_t i = 0; i < size; i++)
        {
            PyList_SetItem(packet_list, i, Py_BuildValue("s#", packets_queue.front().buf, packets_queue.front().len));
            packets_queue.pop();
        }

        return packet_list;
    }
    else
        Py_RETURN_NONE;
}

static PyObject *set_iocap(PyObject *self, PyObject *args)
{

    if (!PyArg_ParseTuple(args, "i", &blehost->io_capability))
    {
        return NULL;
    }

    Py_RETURN_NONE;
}

static PyObject *get_iocap(PyObject *self, PyObject *args)
{

    return Py_BuildValue("i", blehost->io_capability);
}

static void hci_callback(const struct iovec *iov, int iovlen,
                         void *user_data)
{
    struct PACKET hci_packet;

    //  iovec is an array of IOVs, each IOV is a protocol layer
    for (int i = 0; i < iovlen; ++i)
    {
        // Copy IOVs to a flatted arrat.
        memcpy(hci_packet.buf + hci_packet.len, iov[i].iov_base, iov[i].iov_len);
        hci_packet.len += iov[i].iov_len;
    }

    // Add packets to the queue
    packets_queue.push(hci_packet);
}

static PyObject *configure_connection(PyObject *self, PyObject *args)
{
    Py_buffer master_address, slave_address;
    int slave_address_type;
    uint8_t slave_addr_buffer[6];

    if (!PyArg_ParseTuple(args, "s*s*iii", &master_address, &slave_address, &slave_address_type, &blehost->io_capability, &blehost->auth_req))
    {
        return NULL;
    }

    if (blehost->conns)
        btconn_free(blehost->conns);

    blehost->conn_init = true; // Host is the iniciator the connection

    if (blehost->auth_req & 0x08)
        blehost->sc = true; // Enable host support to BLE Secure connection (BLE 4.2)
    else
        blehost->sc = false;

    if (slave_address_type == 0x00)
        slave_address_type = BDADDR_LE_PUBLIC;
    else
        slave_address_type = BDADDR_LE_RANDOM;

    memcpy(blehost->bdaddr, master_address.buf, 6);
    memcpy(slave_addr_buffer, slave_address.buf, 6);

    ReverseBytes(blehost->bdaddr, 6);
    ReverseBytes(slave_addr_buffer, 6);

    init_conn(blehost, 0, slave_addr_buffer, slave_address_type);
    // Set the receiver address type
    //blehost->conns[0].ra_type = slave_address_type;

    PyBuffer_Release(&slave_address);
    PyBuffer_Release(&master_address);

    Py_RETURN_NONE;
}

static PyObject *pairing_request(PyObject *self, PyObject *args)
{
    bthost_request_auth(blehost, 0);

    if (packets_queue.size())
    {
        PyObject *obj = Py_BuildValue("s#", packets_queue.front().buf, packets_queue.front().len);
        packets_queue.pop();
        return obj;
    }
    Py_RETURN_NONE;
}

static PyObject *set_pin_code(PyObject *self, PyObject *args)
{
    Py_buffer str;

    if (!PyArg_ParseTuple(args, "s*", &str))
    {
        return NULL;
    }

    bthost_set_pin_code(blehost, (const uint8_t *)str.buf, str.len);

    Py_RETURN_NONE;
}

static PyObject *set_local_keys_distribution(PyObject *self, PyObject *args)
{
    Py_buffer str;

    if (!PyArg_ParseTuple(args, "i", &force_local_key_distribution))
    {
        return NULL;
    }

    Py_RETURN_NONE;
}

static PyObject *get_ltk(PyObject *self, PyObject *args)
{
    PyObject *obj = Py_BuildValue("s#", ltk, 16);
    return obj;
}

static void create_ble_host()
{
    blehost = bthost_create();
    bthost_set_send_handler(blehost, hci_callback, NULL);
}

static PyMethodDef module_methods[] = {
    {
        "send_hci",
        send_hci,
        METH_VARARGS,
        "Send HCI raw packet to the SMP server.\nA successful processing will return a string response\nError will return None",
    },
    {
        "set_iocap",
        set_iocap,
        METH_VARARGS,
        "Set IO capabilities. Default is 0x03",
    },
    {
        "get_iocap",
        get_iocap,
        METH_NOARGS,
        "Receive IO capabilities. Default is 0x03",
    },
    {
        "configure_connection",
        configure_connection,
        METH_VARARGS,
        "Configure the SMP master addr., slave addr., slave addr. type, iocap and auth request.",
    },
    {
        "pairing_request",
        pairing_request,
        METH_NOARGS,
        "Returns a pairing request raw HCI packet.",
    },
    {
        "set_pin_code",
        set_pin_code,
        METH_VARARGS,
        "Set Pin code.",
    },
    {
        "set_local_key_distribution",
        set_local_keys_distribution,
        METH_VARARGS,
        "Force the loacl keys to distribute.",
    },
    {
        "get_ltk",
        get_ltk,
        METH_NOARGS,
        "Return last calculated ltk from SMP server.",
    },
    {NULL, NULL, 0, NULL}, // sentinel
};

#if PY_MAJOR_VERSION >= 3
static PyModuleDef module_definition = {
    PyModuleDef_HEAD_INIT,
    MODULE_NAME,
    MODULE_DESCRIPTION,
    -1,
    module_methods,
};

PyMODINIT_FUNC PyInit_BLESMPServer()
{
    PyObject *module;

    create_ble_host();

    module = PyModule_Create(&module_definition);
    if (module == NULL)
    {
        return NULL;
    }
    PythonError = PyErr_NewException(MODULE_NAME ".Error", NULL, NULL);
    Py_INCREF(PythonError);
    PyModule_AddObject(module, "Error", PythonError);
    return module;
}
#else
PyMODINIT_FUNC initBLESMPServer()
{
    PyObject *module;

    create_ble_host();
    //PySys_WriteStdout("SMP Server initialized\n");

    module = Py_InitModule3(
        MODULE_NAME, module_methods, MODULE_DESCRIPTION);
    if (module == NULL)
    {
        return;
    }
    PythonError = PyErr_NewException((char *)MODULE_NAME ".Error", NULL, NULL);
    Py_INCREF(PythonError);
    PyModule_AddObject(module, "Error", PythonError);
}
#endif