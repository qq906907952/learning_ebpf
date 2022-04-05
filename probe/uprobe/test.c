#include<stdio.h>

void custom_print(char * s){
    printf("%s\r\n",s);
    char ss[] = "it should print sss normally";
    printf("%s\r\n",ss);
}

int main(){
    char a[] = "it should print aaa normally";
    custom_print(a);
    return 0;
}