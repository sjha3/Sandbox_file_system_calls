#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/reg.h>
#include <errno.h>
#include <stdlib.h>
#include <glob.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pwd.h>
#include <sys/user.h>
#include <errno.h>
#include <limits.h>
#include <fnmatch.h>
const int long_size = sizeof(long);
/* get parameters from registers */
void getparam(long params[],pid_t child){
	 
    params[0] = ptrace(PTRACE_PEEKUSER,
                        child, 8 * RDI,
                        NULL);
    params[1] = ptrace(PTRACE_PEEKUSER,
                        child, 8 *RSI,
                        NULL);
    params[2] = ptrace(PTRACE_PEEKUSER,
                        child, 8 * RDX,
                        NULL);
    return;						
}

//=================

void putdata(pid_t child, long addr,
             char *str, int len)
{   char *laddr;
//printf(" add : %ld , str : %s, len : %d\n",addr,str,len);


    int i, j;
    union u {
            long val;
            char chars[long_size];
    }data;
    i = 0;
    int length =  strlen(str);
    j = length / long_size;
    j++;
    laddr = str;
    while(i < j) {
        memcpy(data.chars, laddr, long_size);
        ptrace(PTRACE_POKEDATA, child,
               addr + i * 8, data.val);
        ++i;
        laddr += long_size;
    }
    j = length % long_size;
    //j++;
    if(j != 0) {
        memcpy(data.chars, laddr, j);
        ptrace(PTRACE_POKEDATA, child,
               addr + i * 8, data.val);
    }

}

/* decide whether to allow or block read, write operations */

int allow_block(int final_perm[],int rd_wr)
{
  //printf("inside allow_block\n");
  int i;

 if( (final_perm[0]==0 && final_perm[1] == 0) && (rd_wr == 2)){ //Restrict RD_Write Access
     //printf("STOP : No RD_Write Access and Performing RD_Write operation :: exit with %d\n",EACCES);
      return 0;
   }

  else if ((final_perm[0]==0) && (rd_wr == 0 || rd_wr == 2)){ // Restrict read access from fend
       //printf("STOP : No Read Access and Performing Read operation :: exit with %d\n",EACCES);
       return 0;
      }

  else if( (final_perm[1]==0) && (rd_wr == 1 || rd_wr == 2)){ //Restrict Write Access
      //printf("STOP : No Write Access and Performing Write operation :: exit with %d\n",EACCES);
      return 0;
      }
return 1;
}

void get_conf_perm(char conf[], char *file_name, int *f_perm)
{
  //printf("inside get conf perm\n");
  char *line = (char*)malloc(1000*sizeof(char));;
  FILE *fp;
  int found = 0;
  size_t len=0;
  ssize_t read;
  fp = fopen(conf,"r");
 while(fgets(line, 1000, fp)!=NULL)
 {
  char *fname=(char*)malloc(100*sizeof(char));
  char *perm=(char*)malloc(20*sizeof(char));


  sscanf(line," %s %s",perm,fname);
  //printf(" file : %s len : %d len(perm) :%d perm : %s\n",fname,strlen(fname),strlen(perm),perm);

  int match = fnmatch(fname, file_name, FNM_PATHNAME);

  if (!match){
   found = 1;
   //printf("FNMATCH() Matched\n");
   f_perm[0]=perm[0]-'0';
   f_perm[1]=perm[1]-'0';
   f_perm[2]=perm[2]-'0';
  }

 free(fname); 
 }

  if (found == 0){   /* no match in glob then config param as 1 */
    //printf(" ALL 111111111111 \n");
    f_perm[0]=1;
    f_perm[1]=1;
    f_perm[2]=1;
    }

fclose(fp);
return;
}


void getdata(pid_t child, long addr,
             char *str, int len)
{   char *laddr;
    int i, j;
    union u {
            long val;
            char chars[long_size];
    }data;
    i = 0; 
    len =255;
    j = len / long_size;
    laddr = str;
    while(i < j) {
        data.val = ptrace(PTRACE_PEEKDATA,
                          child, addr + i * 8,
                          NULL);
        memcpy(laddr, data.chars, long_size);
        ++i;
        laddr += long_size;
    }
    j = len % long_size;
    if(j != 0) {
        data.val = ptrace(PTRACE_PEEKDATA,
                          child, addr + i * 8,
                          NULL);
        memcpy(laddr, data.chars, j);

    }
    
    str[len] = '\0';
}

//=====================================================
int main(int argc, char* argv[])
{
//  printf("ARGUMENTS PASSED : %s %s %s\n",argv[0],argv[1],argv[2]);
   char *f={"abc.txt",NULL};
   char *end = NULL;          
   int a=0,i=0,m=0,n=1,x=0,exec,k,conf_file=0,found=0;
   size_t len=0;
   ssize_t read;
   char arr[255], conf[100],*line;
   char *perm=(int*)malloc(3*sizeof(int)); // get this value from config file
   int *f_perm=(int*)malloc(3*sizeof(int));
   char *res;
   char buf[PATH_MAX + 1];

   struct fd_name{
     long fd;
     char name[255];
    };
   FILE *fp = NULL;

// creating a file with no rwx permission in tmp, which will be passed for getting EACCES 
   creat("/tmp/aaa.txt", 0066);

// Making a directory with no permission
   mkdir("/tmp/mydir", 0000); 
       


      if(strcmp(argv[1],"-c") == 0){
      //printf("config sign: %s\n",argv[i]);
      strcpy(conf,argv[2]);
      conf_file=1;
      n = n + 2; 
     }

   
    if(conf_file==0){
     glob_t fglob,dglob;
     int i =0;
     glob(".fendrc", GLOB_ERR, NULL, &fglob);
     if(fglob.gl_pathc == 1){
     conf_file=1;
     strcpy(conf,".fendrc");
     }
     else{
         struct passwd *pw = getpwuid(getuid());
         const char *homedir = pw->pw_dir; 
         strcat(homedir,"/.fendrc");
         glob(homedir, GLOB_ERR, NULL, &dglob);
         if(dglob.gl_pathc == 1)
         {
         conf_file=1;
         strcpy(conf,homedir);    
         }     
     }
    
    }
   
    if(conf_file==0){
    printf("Must provide a config file\n");
    exit(EXIT_FAILURE);
    }


/* command : /bin/command1, argments (i.e -p):argn[] , files (i.e.abc.txt) : argm[], config file : conf
 
1.ex = touch abc.txt => command1 = touch, command: /bin/touch, argm[0]:abc.txt 
2.mkdir -p a/b/c => command1 = mkdir, command: mkdir, argm[0] = a/b/c , argn[0] : -p 

*/
   
   pid_t child;
   child = fork();

   if(child == 0) {
      ptrace(PTRACE_TRACEME, 0, NULL, NULL);
      //printf("&&&&c child process &&&&\n");
      //execlp(command,command1,argm[0],NULL) ;// something like this
      //execlp(command,command1,argm1,NULL) ;// something like this
      execvp(argv[n],argv+n);
   }
   else {
      long orig_eax;
      long params[3];
      int val_eax;
      int val_rax;
      int status;
      char *str, *ptr;
      
      int toggle = 0;
      struct fd_name fil[10];
      int *final = (int*)malloc(3*sizeof(int)); // final permission "OS and Config file"
      int *os_perm = (int*)malloc(3*sizeof(int));
           
   while(1) {
         wait(&status);
         if(WIFEXITED(status))
             break;
         orig_eax = ptrace(PTRACE_PEEKUSER,
                           child, 8 * ORIG_RAX,
                           NULL);

// 0 ==  ls mydir ======================================================

         if(orig_eax == SYS_fchmodat) {
            //printf("%d : SYS_fchmodat called\n",++i);
            if(toggle == 0) {
               toggle = 1;
               getparam(params,child);
               str = (char *)malloc(1000*sizeof(char));
               ptr =  (char *)malloc(1000*sizeof(char));
               
               getdata(child, params[1], str, 255);

               realpath(str, buf); // find complete path
               //printf("Absolute path : %s\n",buf);

               get_conf_perm(conf, buf, f_perm);
               //printf("File : %s Config :: read : %d, write : %d ex : %d\n",buf,f_perm[0],f_perm[1],f_perm[2]);
              if(f_perm[2] == 0) //need to fail chmod if execute permission is not there
               {
               char *temp_dir = (char*) malloc(1000*sizeof(char));
               char * str2 = (char*) malloc(1000*sizeof(char));       

               strcpy(temp_dir,"/tmp/mydir/testdir");

               putdata(child, params[1], temp_dir, 1000);
               getdata(child, params[1], str2, 1000);
               //printf(" ****** changed dirname name is %s*********\n",str2);
                 }
              //free(str);                           
            }
            else {
               toggle = 0;
            }
         }


// 0 ==  ls mydir ======================================================

         if(orig_eax == SYS_openat) {
            //printf("%d : SYS_openat called\n",++i);
            if(toggle == 0) {
               toggle = 1;
               getparam(params,child);
               str = (char *)malloc(1000*sizeof(char));
               ptr =  (char *)malloc(1000*sizeof(char));
               
               getdata(child, params[1], str, 255);

               realpath(str, buf); // find complete path
               //printf("Absolute path : %s\n",buf);

               get_conf_perm(conf, buf, f_perm);
               //printf("File : %s Config :: read : %d, write : %d ex : %d\n",buf,f_perm[0],f_perm[1],f_perm[2]);
              if(f_perm[0] == 0) //need to fail mkdir at this condition
               {
               char *temp_dir = (char*) malloc(1000*sizeof(char));
               char * str2 = (char*) malloc(1000*sizeof(char));       

               strcpy(temp_dir,"/tmp/mydir");

               putdata(child, params[1], temp_dir, 1000);
               getdata(child, params[1], str2, 1000);

                 }
              //free(str);                           
            }
            else {
               toggle = 0;
            }
         }

//1 =============================================

         if(orig_eax == SYS_mkdir) {
            //printf("%d : SYS_mkdir called\n",++i);
            if(toggle == 0) {
               toggle = 1;
               getparam(params,child);

               str = (char *)malloc(1000*sizeof(char));
               ptr =  (char *)malloc(1000*sizeof(char));
               
               getdata(child, params[0], str, 255);
               //printf("directory name : %s\n",str);
               const char s[1000] = "/";
               static int cnt = 0;
               const char *str1 = (char *)malloc(1000*sizeof(char));
               //realpath(str, buf); // find complete path
            
               
               if(cnt ==0){
               realpath(str, buf); // find complete path
               //printf("Absolute path : %s\n",buf);
               cnt++;
               }
               else {
               strcat(buf,"/");
               strcat(buf,str);
               cnt++;
               }
               
               //printf("Absolute path : %s\n",buf);

               get_conf_perm(conf, buf, f_perm);
               //printf("File : %s Config :: read : %d, write : %d ex : %d\n",buf,f_perm[0],f_perm[1],f_perm[2]);
              if((f_perm[1] & f_perm[2]) == 0) //need to fail mkdir at this condition
               {
               char *temp_dir = (char*) malloc(100*sizeof(char));
               char * str2 = (char*) malloc(1000*sizeof(char));       
               
               strcpy(temp_dir,"/tmp/mydir/");
               strcat(temp_dir,"testdir");

               //printf("Don't execute mkdir command\n");
                putdata(child, params[0], temp_dir, strlen(temp_dir));

                getdata(child, params[0], str2, 255);
                //printf(" ****** changed dirname name is %s*********\n",str2);
                free(temp_dir);
                 }
              //free(str);
              
             
            }
            else {
               toggle = 0;
            }
         }

//1.1 rmdir =============================================

         if(orig_eax == SYS_rmdir) {
            //printf("%d : SYS_rmdir called\n",++i);
            if(toggle == 0) {
               toggle = 1;
               getparam(params,child);

               str = (char *)malloc(1000*sizeof(char));
               ptr =  (char *)malloc(1000*sizeof(char));
               
               getdata(child, params[0], str, 255);

               //strcpy(str,str);
               realpath(str, buf); // find complete path
               //printf("Absolute path : %s\n",buf);

               get_conf_perm(conf, buf, f_perm);
               //printf("File : %s Config :: read : %d, write : %d ex : %d\n",buf,f_perm[0],f_perm[1],f_perm[2]);
              if(f_perm[1] == 0) //need to fail rmdir at this condition
               {
               char *temp_dir = (char*) malloc(1000*sizeof(char));
               char * str2 = (char*) malloc(1000*sizeof(char));       
               ////printf("no write permission to dir : %s\n",dir_name);
               strcpy(temp_dir,"/tmp/mydir/");
               strcat(temp_dir,"testdir");
               //printf("Don't execute mkdir command\n");

                putdata(child, params[0], temp_dir, 1000);
                getdata(child, params[0], str2, 1000);
                //printf(" ****** changed dirname name is %s*********\n",str2);

                 }
              free(str);
             // free(str1);
             
            }
            else {
               toggle = 0;
            }
         }


// 4 =================================
         else if(orig_eax == SYS_open) {
            //printf("%d SYS_open called\n",++i);

            if(toggle == 0) {
               toggle = 1;
               getparam(params,child);
               //printf("New Open called with %ld, %ld, %ld\n",params[0],(params[1]),params[2]);
               str = (char *)malloc(255*sizeof(char));
             
               getdata(child, params[0], str, 255);
               //memcpy(str, params[0], long_size);
               
               strcpy(fil[a].name,str);  
               long rd_wr = params[1] & 3;

               //printf("==========file name is %s rd_wr is %ld\n",fil[a].name, rd_wr);
               int dir_res = 0;  

               realpath(str, buf); // find complete path
               //printf("Absolute path : %s\n",buf);
               get_conf_perm(conf, buf, f_perm);


                 
               int allow = allow_block(f_perm,rd_wr);         
               //printf("returned value : %d\n",allow);
               if (!allow){
                char * str1 = "/tmp/aaa.txt";
                char *str2 = (char*) malloc(255*sizeof(char));


                putdata(child, params[0], str1, 255);
                getdata(child, params[0], str2, 255);

              }            
               free(str);
              }              
            //}
            
           else {
              toggle = 0;

            }
           }

// 5 ================================================
//handle "rm file"  -> need to look for rm -rf command here
         else if(orig_eax == SYS_faccessat) {     // handle "rm file" command
            //printf("%d SYS_remove called\n",++i);

            if(toggle == 0) {
               toggle = 1;
               getparam(params,child);
               //printf("New Removal called with %ld, %ld, %ld\n",params[0],params[1],(params[2]&3));
               str = (char *)malloc(255*sizeof(char));
             
               getdata(child, params[1], str, 255);
               
               strcpy(fil[a].name,str);  
               long rd_wr = params[2] & 3;

               realpath(str, buf); // find complete path
               //printf("Absolute path : %s\n",buf);
               
               get_conf_perm(conf, buf, f_perm);

               if(f_perm[1] == 0){        // If write permission is not there, don't delete file
               //printf("Don't execute 'remove' command\n");
                char * str1 = "/tmp/aaa.txt";
                char *str2 = (char*) malloc(255*sizeof(char));

                putdata(child, params[1], str1, 255);
                getdata(child, params[1], str2, 255);

               kill(child,SIGTERM);
               exit(EACCES);                
                }
               
              }

          else{
               toggle = 0;
              }                
          }

// 6 =========================================================================
//handle creat()
         else if(orig_eax == SYS_creat) {     // handle "rm file" command
            //printf("%d SYS_creat called\n",++i);

            if(toggle == 0) {
               toggle = 1;
               getparam(params,child);
               //printf("New Creat called with %ld, %ld\n",params[0],params[1]);
               str = (char *)malloc(255*sizeof(char));
             
               getdata(child, params[0], str, 255);
               //memcpy(str, params[0], long_size);
               
               strcpy(fil[a].name,str);  
               long rd_wr = params[1]>>6; //rwxrwxrwx is the format for params[1] in create;

               char *buff = (char*) malloc(255*sizeof(char));
               char *dir_name = (char*) malloc(255*sizeof(char));

               realpath(str, buf); // find complete path
               //printf("Absolute path : %s\n",buf);
               
               get_conf_perm(conf, buf, f_perm);

               char *temp_dir = (char*) malloc(1000*sizeof(char));
               char * str2 = (char*) malloc(1000*sizeof(char));
               // if read/write perm not in conf and doing read/write
               if(f_perm[1] == 0)
	       {        
               //printf("no write permission to dir : %s\n",dir_name);
               strcpy(temp_dir,"/tmp/mydir/");
               strcat(temp_dir,"test.txt");

                putdata(child, params[0], temp_dir, 1000);
                getdata(child, params[0], str2, 1000);
              
               }

              }         
          else{
               toggle = 0;
              }                
          }

// 7 ============================================
// link () command => worries about "w" of directory of target file

         else if(orig_eax == SYS_link) {     // handle "rm file" command
            //printf("%d SYS_link called\n",++i);

            if(toggle == 0) {
               toggle = 1;
               getparam(params,child);
               //printf("New link() called with %ld, %ld, %ld\n",params[0],params[1],(params[2]&3));
               str = (char *)malloc(255*sizeof(char));
             
               getdata(child, params[1], str, 255);
               //memcpy(str, params[0], long_size);
               
               strcpy(fil[a].name,str);  
              
               //printf("==========Target file name is %s \n",fil[a].name);
                
               char *buff = (char*) malloc(255*sizeof(char));
               char *dir_name = (char*) malloc(255*sizeof(char));

               realpath(str, buf); // find complete path
               //printf("Absolute path : %s\n",buf);               
               get_conf_perm(conf, buf, f_perm);

               char *temp_dir = (char*) malloc(1000*sizeof(char));
               char * str2 = (char*) malloc(1000*sizeof(char));
               // if read/write perm not in conf and doing read/write
               if(f_perm[1] == 0)
	       {        
               strcpy(temp_dir,"/tmp/mydir/");
               strcat(temp_dir,"test.txt");
               //printf("Don't execute link command\n");

                putdata(child, params[1], temp_dir, 1000);
                getdata(child, params[1], str2, 1000);

                //printf(" ****** changed file name is %s*********\n",str2);
///=========================
                
               }
              }

          else{
               toggle = 0;
              }                
          } 
// 8 ==================================================
// unlink () command => worries about "w" of directory of target file

         else if(orig_eax == SYS_unlink) {     // handle "rm file" command
            //printf("%d SYS_unlink called\n",++i);

            if(toggle == 0) {
               toggle = 1;

              params[0] = ptrace(PTRACE_PEEKUSER,
                        child, 8 * RDI,
                        NULL);

               //printf("New unlink() called with %ld\n",params[0]);
               str = (char *)malloc(1000*sizeof(char));
             
               getdata(child, params[0], str, 255);
               //memcpy(str, params[0], long_size);
               
               strcpy(fil[a].name,str);  
              
               //printf("==========Target file name is %s \n",fil[a].name);
                
               realpath(str, buf); // find complete path
               //printf("Absolute path : %s\n",buf);
               get_conf_perm(conf, buf, f_perm);
 
               //printf("Config :: read : %d, write : %d ex : %d\n",f_perm[0],f_perm[1],f_perm[2]);
         
               // if read/write perm not in conf and doing read/write
               if(f_perm[1] == 0)
	       {        
               //printf("Don't execute unlink command\n");
              char *temp_dir = (char*) malloc(1000*sizeof(char));
               char * str2 = (char*) malloc(1000*sizeof(char));        
               
               strcpy(temp_dir,"/tmp/mydir/aaa.txt");
               //strcat(temp_dir,"test.txt");
               //printf("Don't execute link command\n");
//=======================
                putdata(child, params[0], temp_dir, 1000);
                getdata(child, params[0], str2, 1000);

                //printf(" ****** changed file name is %s*********\n",str2);
                
               }              
              }

          else{
               toggle = 0;
              }                
          }

// 9========== chmod need execute permission
         else if(orig_eax == SYS_fchmodat) {     // handle "rm file" command
            //printf("%d SYS CHMOD called\n",++i);

            if(toggle == 0) {
               toggle = 1;
               getparam(params,child);
               //printf("New link() called with %ld, %ld, %ld\n",params[0],params[1],(params[2]&3));
               str = (char *)malloc(255*sizeof(char));
             
               getdata(child, params[1], str, 255);
               //memcpy(str, params[0], long_size);
               
               strcpy(fil[a].name,str);  
              
               //printf("==========Target file name is %s \n",fil[a].name);
                
               char *buff = (char*) malloc(255*sizeof(char));
               char *dir_name = (char*) malloc(255*sizeof(char));

               realpath(str, buf); // find complete path
               //printf("Absolute path : %s\n",buf);               
               get_conf_perm(conf, buf, f_perm);

               char *temp_dir = (char*) malloc(1000*sizeof(char));
               char * str2 = (char*) malloc(1000*sizeof(char));
               // if read/write perm not in conf and doing read/write
               if(f_perm[1] == 0)
	       {        
               strcpy(temp_dir,"/tmp/mydir/");
               strcat(temp_dir,"test.txt");
               //printf("Don't execute link command\n");

                putdata(child, params[1], temp_dir, 1000);
                getdata(child, params[1], str2, 1000);

                //printf(" ****** changed file name is %s*********\n",str2);
                
               }
              }

          else{
               toggle = 0;
              }                
          } 

  ptrace(PTRACE_SYSCALL, child, NULL, NULL);
      }
 int perm_f_d = strtol("0777", 0, 8);
 chmod ("/tmp/aaa.txt",perm_f_d);
 remove("/tmp/aaa.txt");

 chmod ("/tmp/mydir",perm_f_d);
 rmdir("/tmp/mydir");
 
 }
   return 0;
}

 
