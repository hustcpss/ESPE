/*
 */

//#define DO_DEBUG

#ifndef DO_DEBUG
#include <Python.h>
#endif

#include <pbc/pbc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>

//params of the CIBPRE
static pairing_t pairing;


int do_InitLib(char *filename_param);

//Load the CIBPRE param
static PyObject *
TEST_PEKS_InitLib(PyObject *self, PyObject *args)
{
    unsigned char *param;

    if(!PyArg_ParseTuple(args, "s",
                         &param))
        return NULL;

    if(!do_InitLib((char *)param))
        return NULL;

    Py_INCREF(Py_None);
    return Py_None;
}

//Re-Encrypt init ciphertext for a person
static PyObject *
TEST_PEKS_do_pairing_and_H2(PyObject *self, PyObject *args)
{
    unsigned char *buffer_c1, *buffer_c2;
    unsigned char buffer_out[128];
    int len_buffer_out;
    int len_buffer_c1, len_buffer_c2;
    PyObject *retval;
    element_t a, b, p;


    if(!PyArg_ParseTuple(args, "s#s#",
                         &buffer_c1, &len_buffer_c1,
                         &buffer_c2, &len_buffer_c2))
    {
        return NULL;
    }

    element_init_G1(a, pairing);
    element_init_G1(b, pairing);
    element_init_GT(p, pairing);

    element_from_hash(a, buffer_c1, len_buffer_c1);
    element_from_bytes(b, buffer_c2);
    element_pairing(p, a, b);
    element_to_bytes(buffer_out, p);

    len_buffer_out = element_length_in_bytes(p);
    retval = (PyObject *)Py_BuildValue("iy#", len_buffer_out,
                                                      buffer_out,
                                                      len_buffer_out);
    element_clear(a);
    element_clear(b);
    element_clear(p);
    return retval;
}

static PyObject *
TEST_PEKS_do_encryption(PyObject *self, PyObject *args)
{
    unsigned char *buffer_c1, *buffer_c2, *buffer_c3;
    unsigned char buffer_out[512], buffer_out2[512], buffer_hash[32];
    int len_buffer_out;
    int len_buffer_c1, len_buffer_c2, len_buffer_c3;
    PyObject *retval;
    element_t a, b, p, r, g;


    if(!PyArg_ParseTuple(args, "s#s#s#",
                         &buffer_c1, &len_buffer_c1,
                         &buffer_c2, &len_buffer_c2,
                         &buffer_c3, &len_buffer_c3))
    {
        return NULL;
    }

    element_init_G1(a, pairing);
    element_init_G1(b, pairing);
    element_init_GT(p, pairing);
    element_init_G1(g, pairing);
    element_init_Zr(r, pairing);

    SHA256(buffer_c1, len_buffer_c1, buffer_hash);
    element_from_hash(a, buffer_hash, 32);
    element_from_bytes(b, buffer_c2);
    element_from_bytes(g, buffer_c3);

    element_random(r);
    element_pow_zn(b, b, r);
    element_pow_zn(g, g, r);
    element_pairing(p, a, b);

    element_to_bytes(buffer_out2, g);
    element_to_bytes(buffer_out, p);

    len_buffer_out = element_length_in_bytes(p);
    retval = (PyObject *)Py_BuildValue("iy#iy#", len_buffer_out,
                                                      buffer_out,
                                                      len_buffer_out,
                                                      128,
                                                      buffer_out2,
                                                      128);
    element_clear(a);
    element_clear(b);
    element_clear(p);
    element_clear(r);
    return retval;
}

static PyObject *
TEST_PEKS_get_g_and_h(PyObject *self, PyObject *args)
{
    element_t g, h, a;
    char buffer_g[512], buffer_h[512];
    PyObject *retval;
    int len_out;

    element_init_G1(g, pairing);
    element_init_G1(h, pairing);
    element_init_Zr(a, pairing);

    element_random(a);
    element_random(g);

    element_pow_zn(h, g, a);
    element_to_bytes(buffer_g, g);
    element_to_bytes(buffer_h, h);
    len_out = element_length_in_bytes(g);

    retval = (PyObject *)Py_BuildValue("iy#iy#", len_out,
                                       buffer_g,
                                       len_out,
                                       len_out,
                                       buffer_h,
                                       len_out);

    element_clear(g);
    element_clear(h);
    element_clear(a);

    return retval;
}

//Re-Encrypt init ciphertext for a person
static PyObject *
TEST_PEKS_calculate_gr_hr(PyObject *self, PyObject *args)
{
    unsigned char *buffer_c1, *buffer_c2;
    unsigned char buffer_out_a[512], buffer_out_b[512];
    int len_buffer_out;
    int len_buffer_c1, len_buffer_c2;
    PyObject *retval;
    element_t a, b, r;


    if(!PyArg_ParseTuple(args, "s#s#",
                         &buffer_c1, &len_buffer_c1,
                         &buffer_c2, &len_buffer_c2))
    {
        return NULL;
    }

    element_init_G1(a, pairing);
    element_init_G1(b, pairing);
    element_init_Zr(r, pairing);

    element_random(r);

    element_from_bytes(a, buffer_c1);
    element_from_bytes(b, buffer_c2);
    element_pow_zn(a, a, r);
    element_pow_zn(b, b, r);
    element_to_bytes(buffer_out_a, a);
    element_to_bytes(buffer_out_b, b);

    len_buffer_out = element_length_in_bytes(a);
    retval = (PyObject *)Py_BuildValue("iy#iy#", len_buffer_out,
                                       buffer_out_a,
                                       len_buffer_out,
                                       len_buffer_c1,
                                       buffer_out_b,
                                       len_buffer_out);
    element_clear(a);
    element_clear(b);
    element_clear(r);
    return retval;
}

int do_InitLib(char *param)
{
    char buffer[1024];

    pairing_init_set_str(pairing, param);

    return 1;
}

void calculate_index(element_t *identity, element_t *idx, int length)
{
    int i,j;
    element_t temp_result;
    element_init_Zr(temp_result, pairing);

    for(i = 0; i <= length; i++)
    {
        element_init_Zr(idx[i], pairing);
        element_set0(idx[i]);
    }
    element_set1(idx[0]);

    for(i = 1; i <= length; i++)
    {
        for ( j = i; j > 0; j--)
        {
            element_mul(temp_result, idx[j-1], identity[i-1]);
            element_add(idx[j], idx[j], temp_result);
        }
    }
}

static PyMethodDef
TEST_PEKSMethods[] = {
    {"InitLib", TEST_PEKS_InitLib, METH_VARARGS},
    {"Pairing_H2", TEST_PEKS_do_pairing_and_H2, METH_VARARGS},
    {"Get_g_an_h", TEST_PEKS_get_g_and_h, METH_VARARGS},
    {"Calculate_gr_hr", TEST_PEKS_calculate_gr_hr, METH_VARARGS},
    {"Encrypt", TEST_PEKS_do_encryption, METH_VARARGS},
    {0, 0, 0},
};

static struct PyModuleDef TEST_PEKS_MOD = {
    PyModuleDef_HEAD_INIT,
    "TEST_PEKS",
    "",
    -1,
    TEST_PEKSMethods,
    NULL,
    NULL,
    NULL,
    NULL
};



/* static struct PyModuleDef TEST_PEKSmodule = */
/* { */
/*     PyModuleDef_HEAD_INIT, */
/*     "TEST_PEKS", */
/*     NULL, */
/*     -1, */
/*     TEST_PEKSMethods */
/* }; */


PyMODINIT_FUNC PyInit_TEST_PEKS(void)
{
    return PyModule_Create(&TEST_PEKS_MOD);
}
