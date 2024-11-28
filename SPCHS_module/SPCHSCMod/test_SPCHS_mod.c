
#define SPCHS_buffer_max_size 512
#define sha_len 32

#ifndef DO_DEBUG
#include <Python.h>
#endif
#include "avltree.h"
#include <pbc/pbc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>


//params of the SPCHS
static pairing_t pairing;
static avl_handle* avl_root = NULL ;
static Pri_data* locate_target;

// ECC
#define ECCPARAM dparam 
static char *aparam =
"type a\n"
"q 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791\n"
"h 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776\n"
"r 730750818665451621361119245571504901405976559617\n"
"exp2 159\n"
"exp1 107\n"
"sign1 1\n"
"sign0 1\n";
static char *dparam =
"type d\n"
"q 15028799613985034465755506450771565229282832217860390155996483840017\n"
"n 15028799613985034465755506450771561352583254744125520639296541195021\n"
"h 1\n"
"r 15028799613985034465755506450771561352583254744125520639296541195021\n"
"a 1871224163624666631860092489128939059944978347142292177323825642096\n"
"b 9795501723343380547144152006776653149306466138012730640114125605701\n"
"k 6\n"
"nk 11522474695025217370062603013790980334538096429455689114222024912184432319228393204650383661781864806076247259556378350541669994344878430136202714945761488385890619925553457668158504202786580559970945936657636855346713598888067516214634859330554634505767198415857150479345944721710356274047707536156296215573412763735135600953865419000398920292535215757291539307525639675204597938919504807427238735811520\n"
"hk 51014915936684265604900487195256160848193571244274648855332475661658304506316301006112887177277345010864012988127829655449256424871024500368597989462373813062189274150916552689262852603254011248502356041206544262755481779137398040376281542938513970473990787064615734720\n"
"coeff0 11975189258259697166257037825227536931446707944682470951111859446192\n"
"coeff1 13433042200347934827742738095249546804006687562088254057411901362771\n"
"coeff2 8327464521117791238079105175448122006759863625508043495770887411614\n"
"nqr 142721363302176037340346936780070353538541593770301992936740616924\n";
static char *gparam =
"type g\n"
"q 503189899097385532598615948567975432740967203\n"
"n 503189899097385532598571084778608176410973351\n"
"h 1\n"
"r 503189899097385532598571084778608176410973351\n"
"a 465197998498440909244782433627180757481058321\n"
"b 463074517126110479409374670871346701448503064\n"
"k 10\n"
"nk 1040684643531490707494989587381629956832530311976146077888095795458709511789670022388326295177424065807612879371896982185473788988016190582073591316127396374860265835641044035656044524481121528846249501655527462202999638159773731830375673076317719519977183373353791119388388468745670818193868532404392452816602538968163226713846951514831917487400267590451867746120591750902040267826351982737642689423713163967384383105678367875981348397359466338807\n"
"hk 4110127713690841149713310614420858884651261781185442551927080083178682965171097172366598236129731931693425629387502221804555636704708008882811353539555915064049685663790355716130262332064327767695339422323460458479884756000782939428852120522712008037615051139080628734566850259704397643028017435446110322024094259858170303605703280329322675124728639532674407\n"
"coeff0 67343110967802947677845897216565803152319250\n"
"coeff1 115936772834120270862756636148166314916823221\n"
"coeff2 87387877425076080433559927080662339215696505\n"
"coeff3 433223145899090928132052677121692683015058909\n"
"coeff4 405367866213598664862417230702935310328613596\n"
"nqr 22204504160560785687198080413579021865783099\n";
/*
static PyMethodDef
test_SPCHS_methods[] = {
    {"Init" , test_SPCHS_mod_init , METH_VARARGS},
    {"SysSetup" ,test_SPCHS_mod_system_setup , METH_VARARGS},
    {"StruInit" ,test_SPCHS_mod_Struct_init , METH_VARARGS},
    {"Case1EncModCalc" , test_SPCHS_mod_Enc_case1_mod_calc , METH_VARARGS},
    {"Case1EncPairing" , test_SPCHS_mod_Enc_case1_pairing , METH_VARARGS} ,
    {"Case1EncPairingafter" , test_SPCHS_mod_Enc_case1_pairing_after , METH_VARARGS} ,
    {"Case2EncModCalc" , test_SPCHS_mod_Enc_case2_mod_calc , METH_VARARGS},
    {"Case2EncPairing" , test_SPCHS_mod_Enc_case2_pairing , METH_VARARGS} ,
    {"Case2EncPairingafter" , test_SPCHS_mod_Enc_case2_pairing_after , METH_VARARGS} , 
    {"CaseEncLocal" , test_SPCHS_mod_Enc_local , METH_VARARGS} , 
    {"Case3StruInit" , test_SPCHS_mod_case3_Struct_init ,METH_VARARGS}, 
    {"Case3EncModCalc" , test_SPCHS_mod_Enc_case3_mod_calc , METH_VARARGS},
    {"Case3EncPairing" , test_SPCHS_mod_Enc_case3_pairing , METH_VARARGS} ,
    {"Case3EncPairingafter" , test_SPCHS_mod_Enc_case3_pairing_after , METH_VARARGS} ,
    {"SysSetupAt" , test_SPCHS_mod_system_setup_alter , METH_VARARGS},
    {"Case3StruInitAt" , test_SPCHS_mod_case3_Struct_init_alter ,METH_VARARGS}, 
    {"Case3EncModCalcAt" , test_SPCHS_mod_Enc_case3_mod_calc_alter , METH_VARARGS},
    {"Case3EncPairingAt" , test_SPCHS_mod_Enc_case3_pairing_alter , METH_VARARGS} ,
    {"Case3EncPairingafterAt" , test_SPCHS_mod_Enc_case3_pairing_after_alter , METH_VARARGS} ,
    {0, 0, 0},
};

*/
int init_ec_lib(const char *param)
{
    pairing_init_set_str(pairing, param);
    return 1;
}

int Pri_cmp (Pri_data* a ,Pri_data* b)
{
    for(int i = 0 ; i < sha_len ; i++)
      {
        if(a->sha_W[i] < b->sha_W[i])return -1;
        if(a->sha_W[i] > b->sha_W[i])return 1;
      }
    return 0;
}

//Load the SPCHS param
static PyObject * test_SPCHS_mod_init(PyObject *self, PyObject *args)
{

    if(!init_ec_lib(ECCPARAM))
        return NULL;

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject * test_SPCHS_mod_system_setup(PyObject *self , PyObject *args)
{
    element_t g , P , s ;
    unsigned char buffer_P[SPCHS_buffer_max_size] , buffer_s[SPCHS_buffer_max_size] , buffer_g[SPCHS_buffer_max_size];
    unsigned int buffer_len_P , buffer_len_s , buffer_len_g;
    PyObject *retval;

    element_init_G1(g, pairing);
    element_init_G1(P, pairing);
    element_init_Zr(s, pairing);
    
    element_random(g);
    element_random(s);
    
    element_pow_zn(P , g , s);
  
    element_to_bytes(buffer_g ,g);
    element_to_bytes(buffer_P , P);
    element_to_bytes(buffer_s , s);

    buffer_len_g = element_length_in_bytes(g);
    buffer_len_P = element_length_in_bytes(P);
    buffer_len_s = element_length_in_bytes(s);
    
    retval = (PyObject *)Py_BuildValue("iy#iy#iy#",
            buffer_len_g , buffer_g , buffer_len_g ,
            buffer_len_P , buffer_P , buffer_len_P ,
            buffer_len_s , buffer_s , buffer_len_s
            );
    
    element_clear(g);
    element_clear(P);
    element_clear(s);

    return retval;

}
static PyObject * test_SPCHS_mod_Struct_init(PyObject *self , PyObject *args)
{
    element_t u , g , Pub ;
    unsigned char *buffer_read_g;
    unsigned char buffer_Pub[SPCHS_buffer_max_size] ,buffer_u[SPCHS_buffer_max_size],buffer_g[SPCHS_buffer_max_size] , buffer_r1[SPCHS_buffer_max_size];
    unsigned int len_read_g , len_Pub , len_g , len_u , len_r1;
    PyObject * ret;
    if(!PyArg_ParseTuple(args , "s#" , &buffer_read_g ,&len_read_g))return NULL;

    element_init_G1(Pub , pairing);
    element_init_G1(g , pairing);
    element_init_Zr(u , pairing);
    //init avl tree
    if(avl_root)avl_free(avl_root);
    avl_root = avl_init(sizeof(Pri_data) , Pri_cmp);

    element_from_bytes(g , buffer_read_g);

    element_random(u);
    element_pow_zn(Pub , g , u);

    element_to_bytes(buffer_Pub , Pub);
    element_to_bytes(buffer_u , u);

    len_Pub = element_length_in_bytes(Pub);
    len_u   = element_length_in_bytes(u);

    ret = (PyObject *)Py_BuildValue("iy#iy#", 
          len_Pub , buffer_Pub ,len_Pub,
          len_u , buffer_u ,len_u
          );

    element_clear(Pub);
    element_clear(g);
    element_clear(u);

    return ret;
}
static PyObject * test_SPCHS_mod_Struct_init_alter(PyObject *self , PyObject *args)
{
    element_t u , g , Pub ;
    unsigned char *buffer_read_g;
    unsigned char buffer_Pub[SPCHS_buffer_max_size] ,buffer_u[SPCHS_buffer_max_size],buffer_g[SPCHS_buffer_max_size] , buffer_r1[SPCHS_buffer_max_size];
    unsigned int len_read_g , len_Pub , len_g , len_u , len_r1;
    PyObject * ret;
    if(!PyArg_ParseTuple(args , "s#" , &buffer_read_g ,&len_read_g))return NULL;

    element_init_G2(Pub , pairing);
    element_init_G2(g , pairing);
    element_init_Zr(u , pairing);
    //init avl tree
    if(avl_root)avl_free(avl_root);
    avl_root = avl_init(sizeof(Pri_data) , Pri_cmp);

    element_from_bytes(g , buffer_read_g);

    element_random(u);
    element_pow_zn(Pub , g , u);

    element_to_bytes(buffer_Pub , Pub);
    element_to_bytes(buffer_u , u);

    len_Pub = element_length_in_bytes(Pub);
    len_u   = element_length_in_bytes(u);

    ret = (PyObject *)Py_BuildValue("iy#iy#", 
          len_Pub , buffer_Pub ,len_Pub,
          len_u , buffer_u ,len_u
          );

    element_clear(Pub);
    element_clear(g);
    element_clear(u);

    return ret;
}
static PyObject * test_SPCHS_mod_system_setup_alter(PyObject *self , PyObject *args)
{
    element_t g , P , s ;
    unsigned char buffer_P[SPCHS_buffer_max_size] , buffer_s[SPCHS_buffer_max_size] , buffer_g[SPCHS_buffer_max_size];
    unsigned int buffer_len_P , buffer_len_s , buffer_len_g;
    PyObject *retval;

    element_init_G2(g, pairing);
    element_init_G2(P, pairing);
    element_init_Zr(s, pairing);
    
    element_random(g);
    element_random(s);
    
    element_pow_zn(P , g , s);
  
    element_to_bytes(buffer_g ,g);
    element_to_bytes(buffer_P , P);
    element_to_bytes(buffer_s , s);

    buffer_len_g = element_length_in_bytes(g);
    buffer_len_P = element_length_in_bytes(P);
    buffer_len_s = element_length_in_bytes(s);
    
    retval = (PyObject *)Py_BuildValue("iy#iy#iy#",
            buffer_len_g , buffer_g , buffer_len_g ,
            buffer_len_P , buffer_P , buffer_len_P ,
            buffer_len_s , buffer_s , buffer_len_s
            );
    
    element_clear(g);
    element_clear(P);
    element_clear(s);

    return retval;

}
static PyObject * test_SPCHS_mod_Case3_Struct_init_alter(PyObject *self , PyObject *args)
{
   element_t u , g , Pub ,g_r1 ,r1;
    unsigned char *buffer_read_g;
    unsigned char buffer_Pub[SPCHS_buffer_max_size] ,buffer_u[SPCHS_buffer_max_size];
    unsigned char buffer_g[SPCHS_buffer_max_size], buffer_g_r1[SPCHS_buffer_max_size];
    unsigned char buffer_r1[SPCHS_buffer_max_size];
    unsigned int len_read_g , len_Pub , len_g , len_u , len_g_r1,len_r1;
    PyObject * ret;
    if(!PyArg_ParseTuple(args , "s#" , &buffer_read_g ,&len_read_g))return NULL;

    element_init_G2(Pub , pairing);
    element_init_G2(g_r1 ,pairing);
    element_init_G2(g , pairing);
    element_init_Zr(u , pairing);
    element_init_Zr(r1 , pairing);


    //init avl tree
    avl_root = avl_init(sizeof(Pri_data) , Pri_cmp);

    element_from_bytes(g , buffer_read_g);

    element_random(u);
    element_pow_zn(Pub , g , u);
    element_random(r1);
    element_pow_zn(g_r1 , g , r1);

    element_to_bytes(buffer_Pub , Pub);
    element_to_bytes(buffer_u , u);
    element_to_bytes(buffer_r1 , r1);
    element_to_bytes(buffer_g_r1 , g_r1);

    len_Pub = element_length_in_bytes(Pub);
    len_u   = element_length_in_bytes(u);
    len_r1  = element_length_in_bytes(r1);
    len_g_r1 = element_length_in_bytes(g_r1);

    ret = (PyObject *)Py_BuildValue("iy#iy#iy#iy#", 
          len_Pub , buffer_Pub  ,len_Pub,
          len_u   , buffer_u    ,len_u,
          len_r1  , buffer_r1   ,len_r1,
          len_g_r1 ,  buffer_g_r1 , len_g_r1
          );

    element_clear(Pub);
    element_clear(g);
    element_clear(u);
    element_clear(r1);
    element_clear(g_r1);

    return ret;
}
static PyObject * test_SPCHS_mod_Enc_case3_mod_calc_alter(PyObject *self , PyObject *args)
{
//reduce scheme
  element_t r2;
  element_t H_W;
  PyObject *ret;

  unsigned char  *buffer_read_W ;
  unsigned int   len_read_W ,len_H_W ,len_r2;
  unsigned char buffer_H_W[SPCHS_buffer_max_size],buffer_r2[SPCHS_buffer_max_size];
  unsigned char sha_W[sha_len] = {0};
  int find_ret;

  element_init_Zr(r2,pairing);
  element_init_G1(H_W,pairing);

  if(!PyArg_ParseTuple(args , "y#"  , & buffer_read_W ,&len_read_W))
  {
    return NULL;
  }
  //HASH W TO BILLER MAP
  //get H(W) in G2 (need todo in G1)
  SHA256(buffer_read_W , len_read_W , sha_W);
  element_from_hash(H_W , sha_W ,sha_len);
  //get r2
  element_random(r2);

  //step exist and not
  Pri_data hidden_stk;

  memcpy( hidden_stk.sha_W ,sha_W , sha_len*sizeof(char) );
  hidden_stk.Pt_u_W_len = 0;
  locate_target = NULL;
  locate_target = avl_find(avl_root , &hidden_stk);
  if(locate_target==NULL)
  {
    //insert into avl tree
    avl_add(avl_root , &hidden_stk);
    locate_target = avl_find(avl_root , &hidden_stk);
    find_ret = 0;
  }
  else
  {
    find_ret = 1; 
  }
  //calc H(w)^r2
  element_pow_zn(H_W , H_W , r2);
  element_to_bytes(buffer_H_W , H_W);
  element_to_bytes(buffer_r2 , r2);

  len_H_W = element_length_in_bytes(H_W);
  len_r2 = element_length_in_bytes(r2);
  
  ret = (PyObject *)Py_BuildValue("iiy#iy#", 
                    find_ret , len_H_W ,buffer_H_W , len_H_W , 
                    len_r2 , buffer_r2 , len_r2
                    );
  
  element_clear(r2);
  element_clear(H_W);

  return ret;

}
static PyObject * test_SPCHS_mod_Enc_case3_pairing_alter(PyObject *self , PyObject *args)
{
//simply like do in PEKS to pairing on server
  unsigned char *buffer_c1, *buffer_c2;
  unsigned char buffer_out[SPCHS_buffer_max_size];
  int len_buffer_out;
  int len_buffer_c1, len_buffer_c2;
  PyObject *retval;
  element_t a, b, p;


  if(!PyArg_ParseTuple(args, "y#y#",
                       &buffer_c1, &len_buffer_c1,
                       &buffer_c2, &len_buffer_c2))
  {
      return NULL;
  }

  element_init_G2(a, pairing);
  element_init_G1(b, pairing);
  element_init_GT(p, pairing);

  element_from_bytes(a, buffer_c1);
  element_from_bytes(b, buffer_c2);
  element_pairing(p, b, a);
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
static PyObject * test_SPCHS_mod_Enc_case3_pairing_after_alter(PyObject *self , PyObject *args)
{
  element_t ePH_W ;
  element_t C1,C2,C3 ,r2 ,u , r1 ,g_r1 ,u_div_r2 ,g_r;
  unsigned int len_r2 , len_ePH_W ,len_u , len_r1 ,len_g_r1;
  unsigned char *buffer_r1 , *buffer_r2 , *buffer_g_r1 ,*buffer_ePH_W ,*buffer_u;
  unsigned int len_buffer_c1 ,len_buffer_c2, len_buffer_c3;
  unsigned char buffer_c1[SPCHS_buffer_max_size] ,buffer_c2[SPCHS_buffer_max_size], buffer_c3[SPCHS_buffer_max_size];
  int find_ret;
  PyObject *ret;

  if(!PyArg_ParseTuple(args , "iy#y#y#y#y#" ,&find_ret , &buffer_r1 , &len_r1 , &buffer_r2, &len_r2, &buffer_g_r1 , &len_g_r1 ,
                                            &buffer_ePH_W , &len_ePH_W , &buffer_u , &len_u ))
  {
      return NULL;
  }

  element_init_Zr(u   , pairing);
  element_init_Zr(r2  , pairing);
  element_init_Zr(r1  , pairing);
  element_init_Zr(u_div_r2  , pairing);

  element_init_G2(g_r1  ,pairing);
  element_init_G2(g_r   ,pairing);
  element_init_GT(ePH_W ,pairing);

  element_init_GT(C1  ,pairing);
  element_init_G2(C2  ,pairing);
  element_init_GT(C3  ,pairing);

  element_from_bytes(r1   ,buffer_r1);
  element_from_bytes(r2   , buffer_r2);
  element_from_bytes(g_r1   , buffer_g_r1);
  element_from_bytes(ePH_W  ,buffer_ePH_W);
  element_from_bytes(u  , buffer_u);

  //calc c[i:2] g^r
  element_pow_zn(C2 , g_r1 , r2);

  //calc C[I:3] e(P, H(w))^r1^r2 
  

  if(find_ret == 0)
  {
  //calc C[i,1] e(P,H(w))^u
    element_div(u_div_r2 , u , r2);    
    element_pow_zn(C1 , ePH_W , u_div_r2);
    element_pow_zn(C3 , ePH_W , r1);
    element_to_bytes(locate_target->Pt_u_W , C3);
  }
  else
  {
    element_from_bytes(C1 , locate_target->Pt_u_W);
    element_pow_zn(C3 , ePH_W , r1);
    element_to_bytes(locate_target->Pt_u_W , C3);

  }

  element_to_bytes(buffer_c1 ,C1);
  element_to_bytes(buffer_c2 ,C2);  

  len_buffer_c1 = element_length_in_bytes(C1);
  len_buffer_c2 = element_length_in_bytes(C2);


  ret = (PyObject *)Py_BuildValue("iy#iy#",
        len_buffer_c1,buffer_c1,len_buffer_c1,
        len_buffer_c2,buffer_c2,len_buffer_c2
        );

  element_clear(u);
  element_clear(r2);
  element_clear(r1);
  element_clear(g_r);
  element_clear(u_div_r2);
  element_clear(g_r1);
  element_clear(ePH_W);
  element_clear(C1);
  element_clear(C2);
  element_clear(C3);

  return ret;
}
static PyObject * test_SPCHS_mod_case3_Struct_init(PyObject *self , PyObject *args)
{
    element_t u , g , Pub ,g_r1 ,r1;
    unsigned char *buffer_read_g;
    unsigned char buffer_Pub[SPCHS_buffer_max_size] ,buffer_u[SPCHS_buffer_max_size];
    unsigned char buffer_g[SPCHS_buffer_max_size], buffer_g_r1[SPCHS_buffer_max_size];
    unsigned char buffer_r1[SPCHS_buffer_max_size];
    unsigned int len_read_g , len_Pub , len_g , len_u , len_g_r1,len_r1;
    PyObject * ret;
    if(!PyArg_ParseTuple(args , "s#" , &buffer_read_g ,&len_read_g))return NULL;

    element_init_G1(Pub , pairing);
    element_init_G1(g , pairing);
    element_init_Zr(u , pairing);
    element_init_Zr(r1 , pairing);
    element_init_G1(g_r1 ,pairing);

    //init avl tree
    avl_root = avl_init(sizeof(Pri_data) , Pri_cmp);

    element_from_bytes(g , buffer_read_g);

    element_random(u);
    element_pow_zn(Pub , g , u);
    element_random(r1);
    element_pow_zn(g_r1 , g , r1);

    element_to_bytes(buffer_Pub , Pub);
    element_to_bytes(buffer_u , u);
    element_to_bytes(buffer_r1 , r1);
    element_to_bytes(buffer_g_r1 , g_r1);

    len_Pub = element_length_in_bytes(Pub);
    len_u   = element_length_in_bytes(u);
    len_r1  = element_length_in_bytes(r1);
    len_g_r1 = element_length_in_bytes(g_r1);

    ret = (PyObject *)Py_BuildValue("iy#iy#iy#iy#", 
          len_Pub , buffer_Pub  ,len_Pub,
          len_u   , buffer_u    ,len_u,
          len_r1  , buffer_r1   ,len_r1,
          len_g_r1 ,  buffer_g_r1 , len_g_r1
          );

    element_clear(Pub);
    element_clear(g);
    element_clear(u);
    element_clear(r1);
    element_clear(g_r1);

    return ret;
}
static PyObject * test_SPCHS_mod_Enc_case3_mod_calc(PyObject *self , PyObject *args)
{
//reduce scheme
  element_t r2;
  element_t H_W;
  PyObject *ret;

  unsigned char  *buffer_read_W ;
  unsigned int   len_read_W ,len_H_W ,len_r2;
  unsigned char buffer_H_W[SPCHS_buffer_max_size],buffer_r2[SPCHS_buffer_max_size];
  unsigned char sha_W[sha_len] = {0};
  int find_ret;

  element_init_Zr(r2,pairing);
  element_init_G2(H_W,pairing);

  if(!PyArg_ParseTuple(args , "y#"  , & buffer_read_W ,&len_read_W))
  {
    return NULL;
  }
  //HASH W TO BILLER MAP
  //get H(W) in G2 (need todo in G1)
  SHA256(buffer_read_W , len_read_W , sha_W);
  element_from_hash(H_W , sha_W ,sha_len);
  //get r2
  element_random(r2);

  //step exist and not
  Pri_data hidden_stk;

  memcpy( hidden_stk.sha_W ,sha_W , sha_len*sizeof(char) );
  hidden_stk.Pt_u_W_len = 0;
  locate_target = NULL;
  locate_target = avl_find(avl_root , &hidden_stk);
  if(locate_target==NULL)
  {
    //insert into avl tree
    avl_add(avl_root , &hidden_stk);
    locate_target = avl_find(avl_root , &hidden_stk);
    find_ret = 0;
  }
  else
  {
    find_ret = 1; 
  }
  //calc H(w)^r2
  element_pow_zn(H_W , H_W , r2);
  element_to_bytes(buffer_H_W , H_W);
  element_to_bytes(buffer_r2 , r2);

  len_H_W = element_length_in_bytes(H_W);
  len_r2 = element_length_in_bytes(r2);
  
  ret = (PyObject *)Py_BuildValue("iiy#iy#", 
                    find_ret , len_H_W ,buffer_H_W , len_H_W , 
                    len_r2 , buffer_r2 , len_r2
                    );
  
  element_clear(r2);
  element_clear(H_W);

  return ret;

}
static PyObject * test_SPCHS_mod_Enc_case3_pairing(PyObject *self , PyObject *args)
{
//simply like do in PEKS to pairing on server
  unsigned char *buffer_c1, *buffer_c2;
  unsigned char buffer_out[SPCHS_buffer_max_size];
  int len_buffer_out;
  int len_buffer_c1, len_buffer_c2;
  PyObject *retval;
  element_t a, b, p;


  if(!PyArg_ParseTuple(args, "y#y#",
                       &buffer_c1, &len_buffer_c1,
                       &buffer_c2, &len_buffer_c2))
  {
      return NULL;
  }

  element_init_G1(a, pairing);
  element_init_G2(b, pairing);
  element_init_GT(p, pairing);

  element_from_bytes(a, buffer_c1);
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
static PyObject * test_SPCHS_mod_Enc_case3_pairing_after(PyObject *self , PyObject *args)
{
  element_t ePH_W ;
  element_t C1,C2,C3 ,r2 ,u , r1 ,g_r1 ,u_div_r2 ,g_r;
  unsigned int len_r2 , len_ePH_W ,len_u , len_r1 ,len_g_r1;
  unsigned char *buffer_r1 , *buffer_r2 , *buffer_g_r1 ,*buffer_ePH_W ,*buffer_u;
  unsigned int len_buffer_c1 ,len_buffer_c2, len_buffer_c3;
  unsigned char buffer_c1[SPCHS_buffer_max_size] ,buffer_c2[SPCHS_buffer_max_size], buffer_c3[SPCHS_buffer_max_size];
  int find_ret;
  PyObject *ret;

  if(!PyArg_ParseTuple(args , "iy#y#y#y#y#" ,&find_ret , &buffer_r1 , &len_r1 , &buffer_r2, &len_r2, &buffer_g_r1 , &len_g_r1 ,
                                            &buffer_ePH_W , &len_ePH_W , &buffer_u , &len_u ))
  {
      return NULL;
  }

  element_init_Zr(u   , pairing);
  element_init_Zr(r2  , pairing);
  element_init_Zr(r1  , pairing);
  element_init_Zr(u_div_r2  , pairing);

  element_init_G1(g_r1  ,pairing);
  element_init_G1(g_r   ,pairing);
  element_init_GT(ePH_W ,pairing);

  element_init_GT(C1  ,pairing);
  element_init_G1(C2  ,pairing);
  element_init_GT(C3  ,pairing);

  element_from_bytes(r1   ,buffer_r1);
  element_from_bytes(r2   , buffer_r2);
  element_from_bytes(g_r1   , buffer_g_r1);
  element_from_bytes(ePH_W  ,buffer_ePH_W);
  element_from_bytes(u  , buffer_u);

  //calc c[i:2] g^r
  element_pow_zn(C2 , g_r1 , r2);

    if(find_ret == 0)
  {
  //calc C[i,1] e(P,H(w))^u
    element_div(u_div_r2 , u , r2);    
    element_pow_zn(C1 , ePH_W , u_div_r2);
    element_pow_zn(C3 , ePH_W , r1);
    element_to_bytes(locate_target->Pt_u_W , C3);
  }
  else
  {
    element_from_bytes(C1 , locate_target->Pt_u_W);
    element_pow_zn(C3 , ePH_W , r1);
    element_to_bytes(locate_target->Pt_u_W , C3);

  }

  element_to_bytes(buffer_c1 ,C1);
  element_to_bytes(buffer_c2 ,C2);  

  len_buffer_c1 = element_length_in_bytes(C1);
  len_buffer_c2 = element_length_in_bytes(C2);


  ret = (PyObject *)Py_BuildValue("iy#iy#",
        len_buffer_c1,buffer_c1,len_buffer_c1,
        len_buffer_c2,buffer_c2,len_buffer_c2
        );

  element_clear(u);
  element_clear(r2);
  element_clear(r1);
  element_clear(g_r);
  element_clear(u_div_r2);
  element_clear(g_r1);
  element_clear(ePH_W);
  element_clear(C1);
  element_clear(C2);
  element_clear(C3);

  return ret;
}
static PyObject * test_SPCHS_mod_Enc_local_alter(PyObject *self , PyObject *args)
{
    element_t r,R,C1,C2,C3;
    element_t g,P,ePH_W;
    element_t H_W,Pt_u_W , u ;
    PyObject *ret;

    unsigned char *buffer_read_P, *buffer_read_W , *buffer_read_g , *buffer_read_u;
    unsigned int  len_read_P , len_read_W , len_read_g, len_read_u , len_P ,len_H_W , len_c1 , len_c2 , len_c3;
    unsigned char sha_W[sha_len] ={0};
    unsigned char buffer_H_W[SPCHS_buffer_max_size],buffer_P[SPCHS_buffer_max_size];
    unsigned char buffer_c1[SPCHS_buffer_max_size],buffer_c2[SPCHS_buffer_max_size],buffer_c3[SPCHS_buffer_max_size];
    int find_ret;

    element_init_Zr(r,pairing);
    //caution !"eye on the field"

    element_init_Zr(u ,pairing);
    element_init_G2(g ,pairing);
    element_init_G2(P ,pairing);
    element_init_G1(H_W,pairing);
    element_init_GT(Pt_u_W,pairing);


    if(!PyArg_ParseTuple(args , "y#y#y#y#" ,  & buffer_read_P ,&len_read_P ,   &buffer_read_g ,&len_read_g , &buffer_read_u , &len_read_u , & buffer_read_W ,&len_read_W))
    {
      return NULL;
    }

    //HASH W TO BILLER MAP
    //get H(W) in G2
    SHA256(buffer_read_W , len_read_W , sha_W);
    element_from_hash(H_W , sha_W ,sha_len);
    //get Pt[u,W] in GT using random
    element_random(Pt_u_W);

    element_from_bytes(P , buffer_read_P);
    element_from_bytes(g , buffer_read_g);
    element_from_bytes(u , buffer_read_u);
    //get r
    element_random(r);
    //step: exist or not
    Pri_data hidden_stk;

    memcpy( hidden_stk.sha_W ,sha_W , sha_len );
    hidden_stk.Pt_u_W_len = 0;
    locate_target = NULL;
    locate_target = avl_find(avl_root , &hidden_stk);
    if(locate_target==NULL)
    {
      element_init_GT(C1 , pairing);
      element_init_G2(C2 , pairing);
      element_init_GT(C3 , pairing);

      element_init_GT(ePH_W , pairing);
      //calc e^(p , H(W)) on local
      element_pairing(ePH_W , H_W ,  P);

      //calc C1
      element_pow_zn(C1 , ePH_W , u);

      //calc C2
      element_pow_zn(C2 , g , r);

      //calc C3
      element_pow_zn(C3 , ePH_W , r);
      element_mul(C3 , C3 , Pt_u_W);

      //insert into avl tree
      element_to_bytes(hidden_stk.Pt_u_W , Pt_u_W);
      hidden_stk.Pt_u_W_len = element_length_in_bytes(Pt_u_W);
      avl_add(avl_root , &hidden_stk);
      locate_target = avl_find(avl_root , &hidden_stk);

      element_to_bytes(buffer_c1, C1);
      element_to_bytes(buffer_c2, C2);
      element_to_bytes(buffer_c3, C3);

      len_c1 = element_length_in_bytes(C1);
      len_c2 = element_length_in_bytes(C2);
      len_c3 = element_length_in_bytes(C3);
      //find result


      ret = (PyObject *)Py_BuildValue("iiy#iy#iy#",find_ret ,
              len_c1 , buffer_c1 , len_c1,
              len_c2 , buffer_c2 , len_c2,
              len_c3 , buffer_c3 , len_c3
              );

      element_clear(ePH_W);
      element_clear(C1);
      element_clear(C2);
      element_clear(C3);
    }
    else
    {

      element_init_GT(R , pairing);
      element_init_GT(ePH_W , pairing);
      element_init_GT(C1 , pairing);
      element_init_G2(C2 , pairing);
      element_init_GT(C3 , pairing);

      //calc e^(p , H(W)) on local
      element_pairing(ePH_W , H_W ,  P);
      //calc C3 e(P,H(W))^r · R
      element_random(R);
      element_pow_zn(C3 , ePH_W , r);
      element_mul(C3 , ePH_W , R);

      //calc C[i,2] g^r
      element_pow_zn(C2 , g , r);

      //calc C1 and update P_t
      element_from_bytes(Pt_u_W , locate_target->Pt_u_W);
      element_set(C1 , Pt_u_W );

      element_to_bytes(locate_target->Pt_u_W , R);
      locate_target->Pt_u_W_len = element_length_in_bytes(R);

      element_to_bytes(buffer_c1, C1);
      element_to_bytes(buffer_c2, C2);
      element_to_bytes(buffer_c3, C3);

      len_c1 = element_length_in_bytes(C1);
      len_c2 = element_length_in_bytes(C2);
      len_c3 = element_length_in_bytes(C3);

      find_ret = 1;

      ret = (PyObject *)Py_BuildValue("iiy#iy#iy#",find_ret ,
              len_c1 , buffer_c1 , len_c1,
              len_c2 , buffer_c2 , len_c2,
              len_c3 , buffer_c3 , len_c3
              );

      element_clear(R);
      element_clear(ePH_W);
      element_clear(C1);
      element_clear(C2);
      element_clear(C3);

    }
    element_clear(u);
    element_clear(r);
    element_clear(g);
    element_clear(P);
    element_clear(H_W);
    element_clear(Pt_u_W);


    return ret;
} 
static PyObject * test_SPCHS_io_speed(PyObject *self , PyObject *args)
{
  element_t test;
  unsigned char * buffer_read_test;
  unsigned int len_test;
  unsigned char buffer_test[SPCHS_buffer_max_size];
  PyObject * ret;
  if(!PyArg_ParseTuple(args , "y#" ,  & buffer_read_test ,&len_test ))
    {
      return NULL;
    }
  element_init_G1(test , pairing);
  element_from_bytes(test , buffer_read_test);
  element_to_bytes(buffer_test , test);
  len_test = element_length_in_bytes(test);
  ret = (PyObject *)Py_BuildValue("iy#", len_test , buffer_test,len_test
              );
  element_clear(test);
  return ret;
} 
static PyObject * test_SPCHS_mod_Enc_local(PyObject *self , PyObject *args)
{
    element_t r,R,C1,C2,C3;
    element_t g,P,ePH_W;
    element_t H_W,Pt_u_W , u ;
    PyObject *ret;

    unsigned char *buffer_read_P, *buffer_read_W , *buffer_read_g , *buffer_read_u;
    unsigned int  len_read_P , len_read_W , len_read_g, len_read_u , len_P ,len_H_W , len_c1 , len_c2 , len_c3;
    unsigned char sha_W[sha_len] ={0};
    unsigned char buffer_H_W[SPCHS_buffer_max_size],buffer_P[SPCHS_buffer_max_size];
    unsigned char buffer_c1[SPCHS_buffer_max_size],buffer_c2[SPCHS_buffer_max_size],buffer_c3[SPCHS_buffer_max_size];
    int find_ret;

    element_init_Zr(r,pairing);
    //caution !"eye on the field"

    element_init_Zr(u ,pairing);
    element_init_G1(g ,pairing);
    element_init_G1(P ,pairing);
    element_init_G2(H_W,pairing);
    element_init_GT(Pt_u_W,pairing);


    if(!PyArg_ParseTuple(args , "y#y#y#y#" ,  & buffer_read_P ,&len_read_P ,   &buffer_read_g ,&len_read_g , &buffer_read_u , &len_read_u , & buffer_read_W ,&len_read_W))
    {
      return NULL;
    }

    //HASH W TO BILLER MAP
    //get H(W) in G2
    SHA256(buffer_read_W , len_read_W , sha_W);
    element_from_hash(H_W , sha_W ,sha_len);
    //get Pt[u,W] in GT using random
    element_random(Pt_u_W);

    element_from_bytes(P , buffer_read_P);
    element_from_bytes(g , buffer_read_g);
    element_from_bytes(u , buffer_read_u);
    //get r
    element_random(r);
    //step: exist or not
    Pri_data hidden_stk;

    memcpy( hidden_stk.sha_W ,sha_W , sha_len );
    hidden_stk.Pt_u_W_len = 0;
    locate_target = NULL;
    locate_target = avl_find(avl_root , &hidden_stk);
    if(locate_target==NULL)
    {
      element_init_GT(C1 , pairing);
      element_init_G1(C2 , pairing);
      element_init_GT(C3 , pairing);

      element_init_GT(ePH_W , pairing);
      //calc e^(p , H(W)) on local
      element_pairing(ePH_W , P ,  H_W);

      //calc C1
      element_pow_zn(C1 , ePH_W , u);

      //calc C2
      element_pow_zn(C2 , g , r);

      //calc C3
      element_pow_zn(C3 , ePH_W , r);
      element_mul(C3 , C3 , Pt_u_W);

      //insert into avl tree
      element_to_bytes(hidden_stk.Pt_u_W , Pt_u_W);
      hidden_stk.Pt_u_W_len = element_length_in_bytes(Pt_u_W);
      avl_add(avl_root , &hidden_stk);
      locate_target = avl_find(avl_root , &hidden_stk);

      element_to_bytes(buffer_c1, C1);
      element_to_bytes(buffer_c2, C2);
      element_to_bytes(buffer_c3, C3);

      len_c1 = element_length_in_bytes(C1);
      len_c2 = element_length_in_bytes(C2);
      len_c3 = element_length_in_bytes(C3);
      //find result


      ret = (PyObject *)Py_BuildValue("iiy#iy#iy#",find_ret ,
              len_c1 , buffer_c1 , len_c1,
              len_c2 , buffer_c2 , len_c2,
              len_c3 , buffer_c3 , len_c3
              );

      element_clear(ePH_W);
      element_clear(C1);
      element_clear(C2);
      element_clear(C3);
    }
    else
    {

      element_init_GT(R , pairing);
      element_init_GT(ePH_W , pairing);
      element_init_GT(C1 , pairing);
      element_init_G1(C2 , pairing);
      element_init_GT(C3 , pairing);

      //calc e^(p , H(W)) on local
      element_pairing(ePH_W , P ,  H_W);
      //calc C3 e(P,H(W))^r · R
      element_random(R);
      element_pow_zn(C3 , ePH_W , r);
      element_mul(C3 , ePH_W , R);

      //calc C[i,2] g^r
      element_pow_zn(C2 , g , r);

      //calc C1 and update P_t
      element_from_bytes(Pt_u_W , locate_target->Pt_u_W);
      element_set(C1 , Pt_u_W );

      element_to_bytes(locate_target->Pt_u_W , R);
      locate_target->Pt_u_W_len = element_length_in_bytes(R);

      element_to_bytes(buffer_c1, C1);
      element_to_bytes(buffer_c2, C2);
      element_to_bytes(buffer_c3, C3);

      len_c1 = element_length_in_bytes(C1);
      len_c2 = element_length_in_bytes(C2);
      len_c3 = element_length_in_bytes(C3);

      find_ret = 1;

      ret = (PyObject *)Py_BuildValue("iiy#iy#iy#",find_ret ,
              len_c1 , buffer_c1 , len_c1,
              len_c2 , buffer_c2 , len_c2,
              len_c3 , buffer_c3 , len_c3
              );

      element_clear(R);
      element_clear(ePH_W);
      element_clear(C1);
      element_clear(C2);
      element_clear(C3);

    }
    element_clear(u);
    element_clear(r);
    element_clear(g);
    element_clear(P);
    element_clear(H_W);
    element_clear(Pt_u_W);


    return ret;
} 
//input: P , W output:r ,
static PyObject * test_SPCHS_mod_Enc_case1_mod_calc(PyObject *self , PyObject *args)
{
    element_t r,r1,r2,r3,R,C1,C2,C3;
    element_t g,P,ePH_Wn,ePH_Wni;
    element_t H_W,Pt_u_W;
    PyObject *ret;

    unsigned char *buffer_read_P, *buffer_read_W , *buffer_read_g;
    unsigned int  len_read_P , len_read_W , len_read_g, len_P ,len_H_W , len_c1 , len_c2 , len_c3 ,len_r3;
    unsigned char sha_W[sha_len] ={0};
    unsigned char buffer_H_W[SPCHS_buffer_max_size],buffer_P[SPCHS_buffer_max_size],buffer_r3[SPCHS_buffer_max_size];
    unsigned char buffer_c1[SPCHS_buffer_max_size],buffer_c2[SPCHS_buffer_max_size],buffer_c3[SPCHS_buffer_max_size];
    int find_ret;

    element_init_Zr(r1,pairing);
    element_init_Zr(r2,pairing);
    element_init_Zr(r3,pairing);
    element_init_Zr(r,pairing);
    //caution !"eye on the field"

    element_init_G1(g ,pairing);
    element_init_G1(P ,pairing);
    element_init_G2(H_W,pairing);
    element_init_GT(Pt_u_W,pairing);


    if(!PyArg_ParseTuple(args , "y#y#y#" ,  & buffer_read_P ,&len_read_P ,   &buffer_read_g ,&len_read_g ,& buffer_read_W ,&len_read_W))
    {
      return NULL;
    }

    //HASH W TO BILLER MAP
    //get H(W) in G2
    SHA256(buffer_read_W , len_read_W , sha_W);
    element_from_hash(H_W , sha_W ,sha_len);
    //get Pt[u,W] in GT using random
    element_random(Pt_u_W);
    //get r=r1·r2·r3
    element_from_bytes(P , buffer_read_P);
    element_from_bytes(g , buffer_read_g);
    //get r
    element_random(r1);
    element_random(r2);
    element_random(r3);
    element_mul(r,r1,r2);
    element_mul(r,r,r3);
    //step: exist or not
    Pri_data hidden_stk;

    memcpy( hidden_stk.sha_W ,sha_W , sha_len );
    hidden_stk.Pt_u_W_len = 0;
    locate_target = NULL;
    locate_target = avl_find(avl_root , &hidden_stk);
    if(locate_target==NULL)
    {

      element_init_G1(C2, pairing);
      //calc p^r1 and H(W)^r2 ready reply
      element_pow_zn(P , P , r1);
      element_pow_zn(H_W , H_W , r2);

      //calc C[i,2] g^r
      element_pow_zn(C2 , g , r);

      //insert into avl tree
      element_to_bytes(hidden_stk.Pt_u_W , Pt_u_W);
      hidden_stk.Pt_u_W_len = element_length_in_bytes(Pt_u_W);
      avl_add(avl_root , &hidden_stk);
      locate_target = avl_find(avl_root , &hidden_stk);

      element_to_bytes(buffer_H_W ,H_W);
      element_to_bytes(buffer_P , P);
      element_to_bytes(buffer_r3 , r3);
      element_to_bytes(buffer_c2  , C2);

      len_P   = element_length_in_bytes(P);
      len_H_W = element_length_in_bytes(H_W);
      len_r3  = element_length_in_bytes(r3);
      len_c2  = element_length_in_bytes(C2);
      //find result
      find_ret = 0;

      ret = (PyObject *)Py_BuildValue("iiy#iy#iy#iy#iy",find_ret,
              len_P , buffer_P , len_P ,
              len_H_W , buffer_H_W , len_H_W,
              hidden_stk.Pt_u_W_len, hidden_stk.Pt_u_W , hidden_stk.Pt_u_W_len,
              len_r3 , buffer_r3 , len_r3,
              len_c2 , buffer_c2 , len_c2
              );
      element_clear(C2);
    }
    else
    {

      element_init_GT(R , pairing);
      element_init_GT(ePH_Wn , pairing);
      element_init_GT(ePH_Wni , pairing);
      element_init_GT(C1 , pairing);
      element_init_G1(C2 , pairing);
      element_init_GT(C3 , pairing);
      //calc on local

      element_from_bytes(ePH_Wn , locate_target->Pt_u_W_n);
      element_invert(ePH_Wni , ePH_Wn);

      //calc C3 e(P,H(W))^r · R
      element_random(R);
      element_pow_zn(ePH_Wn ,ePH_Wn, r);
      element_mul(ePH_Wn , ePH_Wn , ePH_Wni);
      element_mul(C3 , ePH_Wn , R);

      //calc C[i,2] g^r
      element_pow_zn(C2 , g , r);

      //calc C1 and update P_t
      element_from_bytes(Pt_u_W , locate_target->Pt_u_W);
      element_set(C1 , Pt_u_W );

      element_to_bytes(locate_target->Pt_u_W , R);
      locate_target->Pt_u_W_len = element_length_in_bytes(R);
      element_to_bytes(buffer_c1, C1);
      element_to_bytes(buffer_c2, C2);
      element_to_bytes(buffer_c3, C3);

      len_c1 = element_length_in_bytes(C1);
      len_c2 = element_length_in_bytes(C2);
      len_c3 = element_length_in_bytes(C3);

      find_ret = 1;

      ret = (PyObject *)Py_BuildValue("iiy#iy#iy#",find_ret ,
              len_c1 , buffer_c1 , len_c1,
              len_c2 , buffer_c2 , len_c2,
              len_c3 , buffer_c3 , len_c3
              );

      element_clear(R);
      element_clear(ePH_Wn);
      element_clear(ePH_Wni);
      element_clear(C1);
      element_clear(C2);
      element_clear(C3);

    }

    element_clear(r1);
    element_clear(r2);
    element_clear(r3);
    element_clear(r);
    element_clear(g);
    element_clear(P);
    element_clear(H_W);
    element_clear(Pt_u_W);


    return ret;

}
static PyObject * test_SPCHS_mod_Enc_case1_pairing(PyObject *self , PyObject *args)
{
  //simply like do in PEKS to pairing on server
  unsigned char *buffer_c1, *buffer_c2;
  unsigned char buffer_out[SPCHS_buffer_max_size];
  int len_buffer_out;
  int len_buffer_c1, len_buffer_c2;
  PyObject *retval;
  element_t a, b, p;


  if(!PyArg_ParseTuple(args, "y#y#",
                       &buffer_c1, &len_buffer_c1,
                       &buffer_c2, &len_buffer_c2))
  {
      return NULL;
  }

  element_init_G1(a, pairing);
  element_init_G2(b, pairing);
  element_init_GT(p, pairing);

  element_from_bytes(a, buffer_c1);
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

//input H_W ePH_W r3 output C1 C3
static PyObject * test_SPCHS_mod_Enc_case1_pairing_after(PyObject *self , PyObject *args)
{
  element_t ePH_W , Pt_u_W ,ePH_Wi;
  element_t C1,C2,C3 ,r3 ,u;
  unsigned int len_r3 , len_Pt_u_W , len_ePH_W ,len_u;
  unsigned char *buffer_r3, *buffer_Pt_u_W , *buffer_ePH_W ,*buffer_u;
  unsigned int len_buffer_c1 , len_buffer_c3;
  unsigned char buffer_c1[SPCHS_buffer_max_size] , buffer_c3[SPCHS_buffer_max_size];
  PyObject *ret;

  if(!PyArg_ParseTuple(args , "y#y#y#y#" ,&buffer_r3,&len_r3,&buffer_Pt_u_W,&len_Pt_u_W,&buffer_ePH_W,&len_ePH_W ,  &buffer_u , &len_u ))
  {
      return NULL;
  }

  element_init_Zr(u, pairing);
  element_init_Zr(r3 , pairing);
  element_init_GT(ePH_W , pairing);
  element_init_GT(Pt_u_W,pairing);

  element_init_GT(ePH_Wi , pairing);

  element_init_GT(C1, pairing);
  element_init_GT(C3, pairing);

  element_from_bytes(u , buffer_u);
  element_from_bytes(r3 , buffer_r3);
  element_from_bytes(ePH_W ,buffer_ePH_W);
  element_from_bytes(Pt_u_W ,buffer_Pt_u_W);

  //calc C[i,3] e(P,H(W))^r·Pt[u ,W]
  element_pow_zn(ePH_W , ePH_W , r3);
  element_mul(C3 , ePH_W , Pt_u_W);

  //calc C[i,1] e(P,H(W))^u
  element_invert(ePH_Wi , ePH_W);
  element_pow_zn(ePH_W , ePH_W , u);
  element_mul(C1 , ePH_Wi , ePH_W);

  element_to_bytes(buffer_c1 ,C1);
  element_to_bytes(buffer_c3 ,C3);

  len_buffer_c1 = element_length_in_bytes(C1);
  len_buffer_c3 = element_length_in_bytes(C3);

  //save e(P,H(W))^u in avl tree
  memcpy(locate_target->Pt_u_W_n , buffer_c1 , len_buffer_c1);
  locate_target->Pt_u_W_n_len = len_buffer_c1;

  ret = (PyObject *)Py_BuildValue("iy#iy#",
        len_buffer_c1,buffer_c1,len_buffer_c1,
        len_buffer_c3,buffer_c3,len_buffer_c3
          );
  
  element_clear(u);
  element_clear(r3);
  element_clear(ePH_W);
  element_clear(Pt_u_W);
  element_clear(ePH_Wi);
  element_clear(C1);
  element_clear(C3);

  return ret;
}

//in this case is very similar to case 1 ,just not save e(P,H(W))^u
static PyObject * test_SPCHS_mod_Enc_case2_mod_calc(PyObject *self , PyObject *args)
{
  element_t r,r1,r2,r3,R,C1,C2,C3;
  element_t g,P;
  element_t H_W,Pt_u_W;
  PyObject *ret;

  unsigned char *buffer_read_P, *buffer_read_W ,*buffer_read_g;
  unsigned int  len_read_P , len_read_W , len_P ,len_H_W , len_c1 , len_c2 , len_c3 ,len_read_g,len_r3;
  unsigned char sha_W[sha_len] = {0};
  unsigned char buffer_H_W[SPCHS_buffer_max_size],buffer_P[SPCHS_buffer_max_size],buffer_r3[SPCHS_buffer_max_size];
  unsigned char buffer_c1[SPCHS_buffer_max_size],buffer_c2[SPCHS_buffer_max_size],buffer_c3[SPCHS_buffer_max_size];
  int find_ret;

  element_init_Zr(r1,pairing);
  element_init_Zr(r2,pairing);
  element_init_Zr(r3,pairing);
  element_init_Zr(r,pairing);
  //caution !"eye on the field"

  element_init_G1(g ,pairing);
  element_init_G1(P ,pairing);
  element_init_G2(H_W,pairing);
  element_init_GT(Pt_u_W,pairing);


  if(!PyArg_ParseTuple(args , "y#y#y#" ,  & buffer_read_P ,&len_read_P , &buffer_read_g ,&len_read_g,& buffer_read_W ,&len_read_W))
  {
    return NULL;
  }
  //HASH W TO BILLER MAP
  //get H(W) in G2
  SHA256(buffer_read_W , len_read_W , sha_W);
  element_from_hash(H_W , sha_W ,sha_len);
  //get Pt[u,W] in GT random
  element_random(Pt_u_W);
  //get r=r1·r2·r3
  element_from_bytes(P , buffer_read_P);
  element_from_bytes(g , buffer_read_g);

  element_random(r1);
  element_random(r2);
  element_random(r3);
  element_mul(r,r1,r2);
  element_mul(r,r,r3);

  //step exist and not
  Pri_data hidden_stk;

  memcpy( hidden_stk.sha_W ,sha_W , sha_len*sizeof(char) );

  hidden_stk.Pt_u_W_len = 0;
  locate_target = NULL;
  locate_target = avl_find(avl_root , &hidden_stk);
  if(locate_target==NULL)
  {
    element_init_G1(C2, pairing);
    //calc p^r1 and H(W)^r2 ready reply
    element_pow_zn(P , P , r1);
    element_pow_zn(H_W , H_W , r2);

    //calc C[i,2] g^r
    element_pow_zn(C2 , g , r);

    //insert into avl tree
    element_to_bytes(hidden_stk.Pt_u_W , Pt_u_W);
    hidden_stk.Pt_u_W_len = element_length_in_bytes(Pt_u_W);
    avl_add(avl_root , &hidden_stk);
    //locate_target = avl_find(avl_root , &hidden_stk);

    element_to_bytes(buffer_H_W, H_W);
    element_to_bytes(buffer_P  , P);
    element_to_bytes(buffer_r3 , r3);
    element_to_bytes(buffer_c2 , C2);

    len_P   = element_length_in_bytes(P);
    len_H_W = element_length_in_bytes(H_W);
    len_r3  = element_length_in_bytes(r3);
    len_c2  = element_length_in_bytes(C2);
    //find result
    find_ret = 0;

    ret = (PyObject *)Py_BuildValue("iiy#iy#iy#iy#iy#",find_ret,
            len_P , buffer_P , len_P ,
            len_H_W , buffer_H_W , len_H_W,
            hidden_stk.Pt_u_W_len, hidden_stk.Pt_u_W , hidden_stk.Pt_u_W_len,
            len_r3 , buffer_r3 , len_r3,
            len_c2 , buffer_c2 , len_c2
            );
    element_clear(C2);
  }
  else
  {
    element_init_GT(C1, pairing);
    element_init_G1(C2 , pairing);
    element_init_GT(R , pairing);
    //calc not on local

    //calc p^r1 and H(W)^r2 ready reply e(P,H(W))^r
    element_pow_zn(P , P , r1);
    element_pow_zn(H_W , H_W , r2);

    //calc C3 e(P,H(W))^r · R will not finsh at here , just R
    element_random(R);


    //calc C[i,2] g^r
    element_pow_zn(C2 , g , r);

    //calc C1 and update P_t
    element_from_bytes(Pt_u_W , locate_target->Pt_u_W);
    element_set(C1 , Pt_u_W);

    //in this case will calc R and update 
    element_to_bytes(locate_target->Pt_u_W , R);
    locate_target->Pt_u_W_len = element_length_in_bytes(R);

    element_to_bytes(buffer_c1, C1);
    element_to_bytes(buffer_c2, C2);
    element_to_bytes(buffer_r3, r3);
    element_to_bytes(buffer_P,  P);
    element_to_bytes(buffer_H_W,H_W);

    len_c1 = element_length_in_bytes(C1);
    len_c2 = element_length_in_bytes(C2);
    len_r3 = element_length_in_bytes(r3);
    len_P   = element_length_in_bytes(P);
    len_H_W = element_length_in_bytes(H_W);

    find_ret = 1;

    ret = (PyObject *)Py_BuildValue("iiy#iy#iy#iy#iy#iy#",find_ret ,
            len_P , buffer_P , len_P ,
            len_H_W , buffer_H_W , len_H_W,
            locate_target->Pt_u_W_len, locate_target->Pt_u_W , locate_target->Pt_u_W_len,
            len_r3 , buffer_r3 , len_r3,
            len_c2 , buffer_c2 , len_c2,
            len_c1 , buffer_c1 , len_c1
            );

    element_clear(R);
    element_clear(C1);
    element_clear(C2);

  }

  element_clear(r1);
  element_clear(r2);
  element_clear(r3);
  element_clear(r);
  element_clear(g);
  element_clear(P);
  element_clear(H_W);
  element_clear(Pt_u_W);


  return ret;

}
static PyObject * test_SPCHS_mod_Enc_case2_pairing(PyObject *self , PyObject *args)
{
  //simply like do in PEKS to pairing on server
  unsigned char *buffer_c1, *buffer_c2;
  unsigned char buffer_out[SPCHS_buffer_max_size];
  int len_buffer_out;
  int len_buffer_c1, len_buffer_c2;
  PyObject *retval;
  element_t a, b, p;


  if(!PyArg_ParseTuple(args, "y#y#",
                       &buffer_c1, &len_buffer_c1,
                       &buffer_c2, &len_buffer_c2))
  {
      return NULL;
  }

  element_init_G1(a, pairing);
  element_init_G2(b, pairing);
  element_init_GT(p, pairing);

  element_from_bytes(a, buffer_c1);
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
//input H_W ePH_W r3 output C1 C3 different from case1 it need to judge if find key in avl

static PyObject * test_SPCHS_mod_Enc_case2_pairing_after(PyObject *self , PyObject *args)
{
  element_t ePH_W , Pt_u_W_or_R ,ePH_Wi;
  element_t C1,C2,C3,r3,u;
  unsigned int find_ret;
  unsigned int len_r3 , len_Pt_u_W_or_R , len_ePH_W ,len_u;
  unsigned char* buffer_r3, *buffer_Pt_u_W_or_R ,*buffer_ePH_W ,*buffer_u;
  unsigned int len_buffer_c1 , len_buffer_c3;
  unsigned char buffer_c1[SPCHS_buffer_max_size] , buffer_c3[SPCHS_buffer_max_size];

  PyObject *ret;

  if(!PyArg_ParseTuple(args , "iy#y#y#|y#" ,&find_ret , &buffer_r3, &len_r3 , &buffer_Pt_u_W_or_R , &len_Pt_u_W_or_R ,  &buffer_ePH_W, &len_ePH_W , &buffer_u , &len_u))
  {
      return NULL;
  }

  element_init_Zr(r3 , pairing);
  element_init_GT(ePH_W , pairing);
  element_init_GT(Pt_u_W_or_R,pairing);

  element_init_GT(ePH_Wi , pairing);

  element_init_GT(C1 , pairing);
  element_init_GT(C3 , pairing);

  element_from_bytes(r3 , buffer_r3);
  element_from_bytes(ePH_W ,buffer_ePH_W);
  element_from_bytes(Pt_u_W_or_R ,buffer_Pt_u_W_or_R);
  

  //calc C[i,3] e(P,H(W))^r·Pt[u ,W] or calc C[i,3] e(P,H(W))^r·R
  element_pow_zn(ePH_W , ePH_W , r3);
  element_mul(C3 , ePH_W , Pt_u_W_or_R);

  //calc C[i,1] e(P,H(W))^u just not found
  if(!find_ret)
  {
  element_init_G1(u , pairing);
  element_from_bytes(u , buffer_u);

  element_invert(ePH_Wi , ePH_W);
  element_pow_zn(ePH_W , ePH_W , u);
  element_mul(C1 , ePH_Wi , ePH_W);

  element_to_bytes(buffer_c1 , C1);
  element_to_bytes(buffer_c3 , C3);

  len_buffer_c1 = element_length_in_bytes(C1);
  len_buffer_c3 = element_length_in_bytes(C3);

  //save e(P,H(W))^u in avl tree not in there
  /*
  memcpy(locate_target->Pt_u_W_n , buffer_c1 , len_buffer_c1);
  locate_target->Pt_u_W_n_len = len_buffer_c1;
  */
  ret = (PyObject *)Py_BuildValue("iy#iy#",
            len_buffer_c1,buffer_c1,len_buffer_c1,
            len_buffer_c3,buffer_c3,len_buffer_c3
          );
  element_clear(u);
  }
  else // just output C3
  {
    element_to_bytes(buffer_c3 , C3);

    len_buffer_c3 = element_length_in_bytes(C3);

    ret = (PyObject *)Py_BuildValue("iy#",
          len_buffer_c3,buffer_c3,len_buffer_c3
            );
  }
  element_clear(r3);
  element_clear(ePH_W);
  element_clear(Pt_u_W_or_R);
  element_clear(ePH_Wi);
  element_clear(C1);
  element_clear(C3);

  return ret;

}

static PyObject * test_SPCHS_mod_Trapdoor_alter(PyObject *self , PyObject *args)
{
  PyObject * ret;
  element_t H_W , s , Tw;
  unsigned char sha_W[sha_len] = {0};
  unsigned char * buffer_s , * buffer_read_W;
  unsigned int buffer_len_s , len_read_W;
  unsigned char buffer_Tw[SPCHS_buffer_max_size];
  unsigned int len_Tw;
  if(!PyArg_ParseTuple(args , "y#y#" , &buffer_s , &buffer_len_s , &buffer_read_W , &len_read_W))
  {
      return NULL;
  }
  element_init_G1(H_W , pairing);
  element_init_G1(Tw , pairing);
  element_init_Zr(s , pairing);

  SHA256(buffer_read_W , len_read_W , sha_W);
  element_from_hash(H_W , sha_W ,sha_len);
  element_from_bytes(s , buffer_s);

  element_pow_zn(Tw , H_W , s);

  element_to_bytes(buffer_Tw , Tw);
  len_Tw = element_length_in_bytes(Tw);
  
  ret = (PyObject *)Py_BuildValue("iy#",
        len_Tw,buffer_Tw,len_Tw
          );

  element_clear(H_W);
  element_clear(Tw);
  element_clear(s);
 
  return ret;
}

static PyObject * test_SPCHS_mod_Trapdoor(PyObject *self , PyObject *args)
{
  PyObject * ret;
  element_t H_W , s , Tw;
  unsigned char sha_W[sha_len] = {0};
  unsigned char * buffer_s , * buffer_read_W;
  unsigned int buffer_len_s , len_read_W;
  unsigned char buffer_Tw[SPCHS_buffer_max_size];
  unsigned int len_Tw;
  if(!PyArg_ParseTuple(args , "y#y#" , &buffer_s , &buffer_len_s , &buffer_read_W , &len_read_W))
  {
      return NULL;
  }
  element_init_G2(H_W , pairing);
  element_init_G2(Tw , pairing);
  element_init_Zr(s , pairing);

  SHA256(buffer_read_W , len_read_W , sha_W);
  element_from_hash(H_W , sha_W ,sha_len);
  element_from_bytes(s , buffer_s);

  element_pow_zn(Tw , H_W , s);

  element_to_bytes(buffer_Tw , Tw);
  len_Tw = element_length_in_bytes(Tw);

  ret = (PyObject *)Py_BuildValue("iy#",
        len_Tw,buffer_Tw,len_Tw
          );

  element_clear(H_W);
  element_clear(Tw);
  element_clear(s);
 
  return ret;
}

//this para just calc next pointer , the differ is based on specific lang
/*
  EXAMPLE
def StruSearch():
  Pt = test_SPCHS_mod.StructSearch(step1 , Tw)
  for ciper in cipers:
    if Pt == cipher then:
      Ans += cipher
      Pt = test_SPCHS_mod.StructSearch(step2 , Tw , cipher)
  ----------
  This is just a example , you can use more powerful structure
*/
static PyObject* test_SPCHS_mod_case3_StructSearch_base(PyObject *self , PyObject *args)
{
  PyObject * ret;
  element_t Pub , Tw , Pt;
  unsigned char * buffer_1 , * buffer_2;
  unsigned int len_1 , len_2;
  unsigned char buffer_3[SPCHS_buffer_max_size];
  unsigned int len_3;
  if(!PyArg_ParseTuple(args , "y#y#"  , &buffer_1 , &len_1 , &buffer_2 , &len_2))
  {
      return NULL;
  }
  // in this case buffer1 = Pub buffer2 = Tw 
  element_init_G1(Pub , pairing);
  element_init_G2(Tw , pairing);
  element_init_GT(Pt , pairing);
  element_from_bytes(Pub , buffer_1);
  element_from_bytes(Tw , buffer_2);

  element_pairing(Pt , Pub , Tw);

  element_to_bytes(buffer_3 , Pt);
  len_3 = element_length_in_bytes(Pt);

  ret = (PyObject *)Py_BuildValue("iy#",
        len_3,buffer_3,len_3
          );

  element_clear(Pub);
  element_clear(Tw);
  element_clear(Pt);

  return ret;
}
//this para just calc next pointer , the differ is based on specific lang
static PyObject* test_SPCHS_mod_case3_StructSearch_base_alter(PyObject *self , PyObject *args)
{
  PyObject * ret;
  element_t Pub , Tw , Pt ;
  unsigned char * buffer_1 , * buffer_2;
  unsigned int len_1 , len_2;
  unsigned char buffer_3[SPCHS_buffer_max_size];
  unsigned int len_3;
  if(!PyArg_ParseTuple(args , "y#y#" , &buffer_1 , &len_1 , &buffer_2 , &len_2))
  {
      return NULL;
  }
  // in this case buffer1 = Pub buffer2 = Tw 
  element_init_G2(Pub , pairing);
  element_init_G1(Tw , pairing);
  element_init_GT(Pt , pairing);
  element_from_bytes(Pub , buffer_1);
  element_from_bytes(Tw , buffer_2);

  element_pairing(Pt , Tw , Pub);

  element_to_bytes(buffer_3 , Pt);
  len_3 = element_length_in_bytes(Pt);

  ret = (PyObject *)Py_BuildValue("iy#",
        len_3,buffer_3,len_3
          );

  element_clear(Pub);
  element_clear(Tw);
  element_clear(Pt);

  return ret;
}
//general get a lib
static PyMethodDef
test_SPCHS_methods[] = {
    {"Init" , test_SPCHS_mod_init , METH_VARARGS},
    {"SysSetup" ,test_SPCHS_mod_system_setup , METH_VARARGS},
    {"StruInit" ,test_SPCHS_mod_Struct_init , METH_VARARGS},
    {"SysSetupAt" , test_SPCHS_mod_system_setup_alter , METH_VARARGS},
    {"StruInitAt" , test_SPCHS_mod_Struct_init_alter ,METH_VARARGS},
    {"Case1EncModCalc" , test_SPCHS_mod_Enc_case1_mod_calc , METH_VARARGS},
    {"Case1EncPairing" , test_SPCHS_mod_Enc_case1_pairing , METH_VARARGS} ,
    {"Case1EncPairingafter" , test_SPCHS_mod_Enc_case1_pairing_after , METH_VARARGS} ,
    {"Case2EncModCalc" , test_SPCHS_mod_Enc_case2_mod_calc , METH_VARARGS},
    {"Case2EncPairing" , test_SPCHS_mod_Enc_case2_pairing , METH_VARARGS} ,
    {"Case2EncPairingafter" , test_SPCHS_mod_Enc_case2_pairing_after , METH_VARARGS} , 
    {"CaseEncLocal" , test_SPCHS_mod_Enc_local , METH_VARARGS} ,
    {"CaseEncLocalAt" , test_SPCHS_mod_Enc_local_alter , METH_VARARGS} ,
    {"Case3StruInit" , test_SPCHS_mod_case3_Struct_init ,METH_VARARGS}, 
    {"Case3EncModCalc" , test_SPCHS_mod_Enc_case3_mod_calc , METH_VARARGS},
    {"Case3EncPairing" , test_SPCHS_mod_Enc_case3_pairing , METH_VARARGS} ,
    {"Case3EncPairingafter" , test_SPCHS_mod_Enc_case3_pairing_after , METH_VARARGS} ,
    {"Case3StruInitAt" , test_SPCHS_mod_Case3_Struct_init_alter ,METH_VARARGS}, 
    {"Case3EncModCalcAt" , test_SPCHS_mod_Enc_case3_mod_calc_alter , METH_VARARGS},
    {"Case3EncPairingAt" , test_SPCHS_mod_Enc_case3_pairing_alter , METH_VARARGS} ,
    {"Case3EncPairingafterAt" , test_SPCHS_mod_Enc_case3_pairing_after_alter , METH_VARARGS} ,
    {"Iospeed" ,test_SPCHS_io_speed ,METH_VARARGS},
    {"TrapDoor" , test_SPCHS_mod_Trapdoor ,METH_VARARGS},
    {"TrapDoorAt" , test_SPCHS_mod_Trapdoor_alter , METH_VARARGS},
    {"Case3StruSearch" , test_SPCHS_mod_case3_StructSearch_base , METH_VARARGS},
    {"Case3StruSearchAt" , test_SPCHS_mod_case3_StructSearch_base_alter , METH_VARARGS},
    {0, 0, 0},
};

static struct PyModuleDef
test_SPCHS_mod = {
    PyModuleDef_HEAD_INIT,
    "test_SPCHS_mod",
    "",
    -1,
    test_SPCHS_methods,
    NULL,
    NULL,
    NULL,
    NULL
};


PyMODINIT_FUNC PyInit_test_SPCHS_mod(void)
{
    return PyModule_Create(&test_SPCHS_mod);
}

