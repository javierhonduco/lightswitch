      PROGRAM TEST1
C
C  THIS PROGRAM CONTAINS SEVERAL FUNCTIONS THAT WILL
C  ALLOW TESTING OF FORTRAN STACK UNWINDING
C  OPTIONS COMPILED WITH:
C  -g -O0 -Wall -std=legacy
C
#if NOINLINE
      !GCC$ ATTRIBUTES NOINLINE :: A1, A2, B1, B2, C1, C2, TOP1, TOP2
#endif
C  DECLARE FUNCTIONS
C
      INTEGER A1, A2
      INTEGER RES
C
      DO WHILE (1.EQ.1)
C        PRINT*, 'THIS IS A TEST'
         RES = A1()
         RES = A2()
      END DO
C
      STOP
      END

      INTEGER FUNCTION A1()
#if NOINLINE
      !GCC$ ATTRIBUTES NOINLINE :: A1
#endif
         INTEGER RES, B1
         RES = B1()
         A1=1
         RETURN
      END

      INTEGER FUNCTION A2()
#if NOINLINE
      !GCC$ ATTRIBUTES NOINLINE :: A2
#endif
         INTEGER B2, RES
         RES=B2()
         A2=1
         RETURN
      END

      INTEGER FUNCTION B2()
#if NOINLINE
      !GCC$ ATTRIBUTES NOINLINE :: B2
#endif
         INTEGER C2, RES
         RES=C2()
         B2=1
         RETURN
      END

      INTEGER FUNCTION C2()
#if NOINLINE
      !GCC$ ATTRIBUTES NOINLINE :: C2
#endif
         INTEGER TOP2, RES
         RES=TOP2()
         C2=1
         RETURN
      END


      INTEGER FUNCTION B1()
#if NOINLINE
      !GCC$ ATTRIBUTES NOINLINE :: B1
#endif
         INTEGER C1, RES
         RES = C1()
         B1=1
         RETURN
      END

      INTEGER FUNCTION C1()
#if NOINLINE
      !GCC$ ATTRIBUTES NOINLINE :: C1
#endif
         INTEGER TOP1, RES
         RES = TOP1()
         C1=1
         RETURN
      END

      INTEGER FUNCTION TOP1()
#if NOINLINE
      !GCC$ ATTRIBUTES NOINLINE :: TOP1
#endif
         INTEGER I, RES
         DO I = 0, 1000, 1
           PRINT *, 'TOP1: ', I
           RES=I
         END DO
         TOP1 = 0
         RETURN
      END

      INTEGER FUNCTION TOP2()
#if NOINLINE
      !GCC$ ATTRIBUTES NOINLINE :: TOP2
#endif
         INTEGER I, RES
         DO I = 0, 1000, 1
           PRINT *, 'TOP2: ', I
           RES=I
         END DO
         TOP2 = 0
         RETURN
      END

