#include <stdio.h>
#include <stdint.h>

typedef struct
{

    void *fptr1;
    void *fptr2;
} f_op_struct;

int f1()
{
    int x2 = 1234;
    return x2;
}
int f2()
{
    int x3 = 23444;
    return 3;
}

f_op_struct g_fop = {
    .fptr1 = f1,
    .fptr2 = (void *)f2,
};

struct xxx_t {
    void * attrs[20];
};

int smc_nl_remove_ueid(void *a1, struct xxx_t *info)
{


    int x1 = info->attrs[1];
    int x2 = info->attrs[2];

    sink(x1);

    sink(x2);

    sink1(info->attrs[1]);
    sink1((unsigned long)info->attrs[3]);
    // sink1(info->attrs);
    // sink1(info[1]);

    // void *v2 = evil2(evil1(info), 122);
    // void *v3 = evil3(v2, 333);

    // sink1(v3);
}

struct a_struct_type {
    void * foo;
};

void bad(struct a_struct_type *a_struct)
{
    void *x = NULL;
    a_struct->foo = x;
    free(x);
}

void *bad22()
{
    void *x = NULL;
    int cond = 2;
    if (cond)
        free(x);

    *(unsigned int *)x = 123;

    return x;
}

void use_arg_without_check_len1(int a1, unsigned char *data, int len)
{
    int x = *(unsigned int *)(data + 8);
    return x * 2;
}

void use_arg_without_check_len2(int a1, unsigned char *data, int len)
{
    int x = *(unsigned int *)(data + 8);

    if (len < 4)
    {
        return -1;
    }

    return x * 2;
}

void use_arg_without_check_len3(int a1, unsigned char *data, int len)
{

    if (len < 4)
    {
        return -1;
    }

    int x = *(unsigned int *)(data + 8);

    return x * 2;
}


struct xxxxx_t
{
    int x1;
    int x2;
};

// ok
void array_oob_from_buffer1(int a1, int *array, unsigned char* data) {
    struct xxxxx_t* xt = data;
    array[xt->x2] = 0;
}

void array_oob_from_buffer1_1(int a1, int *array, unsigned char* data) {
    struct xxxxx_t* xt = data;
    int idx = xt->x2;
    array[idx] = 0;
}

void array_oob_from_buffer1_2(int a1, int *array, unsigned char* data) {
    struct xxxxx_t* xt = (struct xxxxx_t*)data;
    int idx;
    idx = xt->x2;
    array[idx] = 0;
}


void array_oob_from_buffer1_3(int a1, int *array, unsigned char* data) {
    struct xxxxx_t xt = *(struct xxxxx_t*)data;
    int idx;
    idx = xt.x2;
    array[idx] = 0;
}

void array_oob_from_buffer2(int a1, int *array, unsigned char* data) {
    int idx = *(int*)data;
    array[idx] = 0;
}

void array_oob_from_buffer2_ok(int a1, int *array, unsigned char* data) {
    int idx = data[3];
    array[idx] = 0;
}

void array_oob_from_buffer3(int a1, int *array, unsigned char* data) {
    int idx = *(int *)(data + 8);
    array[idx] = 0;
}


int dbg_flow2(unsigned long x) {
    return x + 2;
}



int dbg_flow1(unsigned long x) {
    return 0;
}



void array_oob_from_buffer4(int a1, int *array, unsigned char* data) {
    int *int_ptr = (int *)(data + 8);
    int idx = *int_ptr;

    dbg_sink(idx);

    if(idx > 8) {
        return -1;
    }
    array[idx] = 0;

    dbg_sink3(array[idx]);

    int y = dbg_sink2((unsigned long)idx);

    int z= dbg_flow2(y);
    int k = dbg_flow1(z);

    dbg_sink4(y);
    if(k > 20) {
        return y;
    }

    return dbg_sink5((unsigned long)y);

}

void array_oob_from_buffer4_def(int a1, int *array, unsigned char* data) {
    int *int_ptr = (int *)(data + 8);
    int idx = int_ptr[0];

    int buffer[10] = {0};

    dbg_sink(idx);

    buffer[idx] = 1;

    if(idx > 8) {
        return -1;
    }
    array[idx] = 0;

    dbg_sink3(array[idx]);

    dbg_sink2(idx);

}