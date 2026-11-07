/* SPDX-License-Identifier: GPL-2.0-only */
static int ascent_main(int argc,char **argv){
 if(argc==2&&!strcmp(argv[1],"--ascent-capabilities")){
#ifdef _WIN32
 const char *host="windows";
#else
 const char *host="linux";
#endif
 printf("{\"schema\":\"ascent.ubifs.helper.v1\",\"inventory_schema\":\"ascent.ubifs.inventory.v1\",\"metadata\":true,\"host\":\"%s\"}\n",host);return 0;}
 if(argc==2&&!strcmp(argv[1],"--version")){puts("mkfs.ubifs (mtd-utils) 2.2.0 ASCENT inventory adapter 3");return 0;}
 int found=0;for(int i=1;i<argc;i++)if(!strcmp(argv[i],"--ascent-inventory")){if(found||i+1>=argc)invalid("inventory argument");load_inventory(argv[i+1]);memmove(argv+i,argv+i+2,(argc-i-1)*sizeof(char*));argc-=2;found=1;break;}
 if(!found)invalid("--ascent-inventory required");
 /* Deliberately expose only the geometry interface consumed by AC. */
 const char *allowed[]={"-r","-o","-m","-e","-c","-x","-k","-f","-l","-p","-j","-F"};unsigned seen=0;
 for(int i=1;i<argc;i++){int option=-1;for(int j=0;j<12;j++)if(!strcmp(argv[i],allowed[j]))option=j;if(option<0||(seen&(1u<<option)))invalid("unsupported/duplicate mkfs option");seen|=1u<<option;if(option==11)continue;if(++i>=argc)invalid("missing mkfs argument");if(option==5&&strcmp(argv[i],"zlib"))invalid("zlib required");if(option==6&&strcmp(argv[i],"r5"))invalid("r5 required");}
 if((seen&3)!=3)invalid("explicit payload root and file output required");
 return upstream_main(argc,argv);
}
#ifdef _WIN32
int wmain(int argc,wchar_t **wargv){char **argv=calloc(argc+1,sizeof(char*));for(int i=0;i<argc;i++){int n=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,wargv[i],-1,NULL,0,NULL,NULL);if(!n)return 2;argv[i]=malloc(n);if(!WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,wargv[i],-1,argv[i],n,NULL,NULL))return 2;}return ascent_main(argc,argv);}
#else
int main(int argc,char **argv){return ascent_main(argc,argv);}
#endif
