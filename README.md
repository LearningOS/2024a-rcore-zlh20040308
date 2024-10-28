# rCore-Camp-Code-2024A

### Code
- [Soure Code of labs for 2024A](https://github.com/LearningOS/rCore-Camp-Code-2024A)
### Documents

- Concise Manual: [rCore-Camp-Guide-2024A](https://LearningOS.github.io/rCore-Camp-Guide-2024A/)

- Detail Book [rCore-Tutorial-Book-v3](https://rcore-os.github.io/rCore-Tutorial-Book-v3/)


### OS API docs
- [ch1](https://learningos.github.io/rCore-Camp-Code-2024A/ch1/os/index.html) [ch2](https://learningos.github.io/rCore-Camp-Code-2024A/ch2/os/index.html) [ch3](https://learningos.github.io/rCore-Camp-Code-2024A/ch3/os/index.html) [ch4](https://learningos.github.io/rCore-Camp-Code-2024A/ch4/os/index.html)
- [ch5](https://learningos.github.io/rCore-Camp-Code-2024A/ch5/os/index.html) [ch6](https://learningos.github.io/rCore-Camp-Code-2024A/ch6/os/index.html) [ch7](https://learningos.github.io/rCore-Camp-Code-2024A/ch7/os/index.html) [ch8](https://learningos.github.io/rCore-Camp-Code-2024A/ch8/os/index.html)


### Related Resources
- [Learning Resource](https://github.com/LearningOS/rust-based-os-comp2022/blob/main/relatedinfo.md)


### Build & Run

Replace `<YourName>` with your github ID, and replace `<Number>` with the chapter ID.

Notice: `<Number>` is chosen from `[1,2,3,4,5,6,7,8]`

```bash
# 
$ git clone git@github.com:LearningOS/2024a-rcore-<YourName>
$ cd 2024a-rcore-<YourName>
$ git clone git@github.com:LearningOS/rCore-Tutorial-Test-2024A user
$ git checkout ch<Number>
$ cd os
$ make run
```

### Grading

Replace `<YourName>` with your github ID, and replace `<Number>` with the chapter ID.

Notice: `<Number>` is chosen from `[3,4,5,6,8]`

```bash
# Replace <YourName> with your github ID 
$ git clone git@github.com:LearningOS/2024a-rcore-<YourName>
$ cd 2024a-rcore-<YourName>
$ rm -rf ci-user
$ git clone git@github.com:LearningOS/rCore-Tutorial-Checker-2024A ci-user
$ git clone git@github.com:LearningOS/rCore-Tutorial-Test-2024A ci-user/user
$ git checkout ch<Number>
$ cd ci-user
$ make test CHAPTER=<Number>
```
ch8_deadlock_sem1
ch8_deadlock_sem2
[ INFO] sys_semaphore_create
[ INFO] available = [3] ,allocation = [[0]] ,need = [[0]]
[ INFO] kernel:pid[2] tid[0] sys_semaphore_down sem_id = 0
[ INFO] available = [3] ,allocation = [[0]] ,need = [[0]]
[ INFO] kernel:pid[2] tid[0] sys_semaphore_down sem_id = 0
[ INFO] available = [2] ,allocation = [[1]] ,need = [[0]]
[ INFO] kernel:pid[2] tid[0] sys_semaphore_down sem_id = 0
[ INFO] available = [1] ,allocation = [[2]] ,need = [[0]]
[ INFO] sys_semaphore_create
[ INFO] available = [0, 1] ,allocation = [[3, 0]] ,need = [[0, 0]]
[ INFO] sys_semaphore_create
[ INFO] available = [0, 1, 2] ,allocation = [[3, 0, 0]] ,need = [[0, 0, 0]]
[ INFO] sys_semaphore_create
[ INFO] available = [0, 1, 2, 1] ,allocation = [[3, 0, 0, 0]] ,need = [[0, 0, 0, 0]]
Thread 1 started.
Thread 1 is allocating resources.
[ INFO] kernel:pid[2] tid[1] sys_semaphore_down sem_id = 2
[ INFO] available = [0, 1, 2, 1] ,allocation = [[3, 0, 0, 0], [0, 0, 0, 0]] ,need = [[0, 0, 0, 0], [0, 0, 0, 0]]
[ INFO] kernel:pid[2] tid[1] sys_semaphore_down sem_id = 0
[ INFO] available = [0, 1, 1, 1] ,allocation = [[3, 0, 0, 0], [0, 0, 1, 0]] ,need = [[0, 0, 0, 0], [0, 0, 0, 0]]
[ INFO] work = [0, 1, 1, 1]
[ INFO] process_inner.need[0] = [0, 0, 0, 0]
[ INFO] bigger = true
[ INFO] work = [3, 1, 1, 1]
[ INFO] process_inner.need[1] = [1, 0, 0, 0]
[ INFO] bigger = true
[ INFO] finish = [true, true]
[ INFO] We are safe..............
[ INFO] tid[1] gonna sleep
[ INFO] need = [[0, 0, 0, 0], [1, 0, 0, 0]]
Thread 2 started.
Thread 2 is allocating resources.
[ INFO] kernel:pid[2] tid[2] sys_semaphore_down sem_id = 1
[ INFO] available = [0, 1, 1, 1] ,allocation = [[3, 0, 0, 0], [0, 0, 1, 0], [0, 0, 0, 0], [0, 0, 0, 0]] ,need = [[0, 0, 0, 0], [1, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0]]
[ INFO] kernel:pid[2] tid[2] sys_semaphore_down sem_id = 2
[ INFO] available = [0, 0, 1, 1] ,allocation = [[3, 0, 0, 0], [0, 0, 1, 0], [0, 1, 0, 0], [0, 0, 0, 0]] ,need = [[0, 0, 0, 0], [1, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0]]
[ INFO] kernel:pid[2] tid[2] sys_semaphore_down sem_id = 0
[ INFO] available = [0, 0, 0, 1] ,allocation = [[3, 0, 0, 0], [0, 0, 1, 0], [0, 1, 1, 0], [0, 0, 0, 0]] ,need = [[0, 0, 0, 0], [1, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0]]
[ INFO] work = [0, 0, 0, 1]
[ INFO] process_inner.need[0] = [0, 0, 0, 0]
[ INFO] bigger = true
[ INFO] work = [3, 0, 0, 1]
[ INFO] process_inner.need[1] = [1, 0, 0, 0]
[ INFO] bigger = true
[ INFO] work = [3, 0, 1, 1]
[ INFO] process_inner.need[2] = [1, 0, 0, 0]
[ INFO] bigger = true
[ INFO] work = [3, 1, 2, 1]
[ INFO] process_inner.need[3] = [0, 0, 0, 0]
[ INFO] bigger = true
[ INFO] finish = [true, true, true, true]
[ INFO] We are safe..............
[ INFO] tid[2] gonna sleep
[ INFO] need = [[0, 0, 0, 0], [1, 0, 0, 0], [1, 0, 0, 0], [0, 0, 0, 0]]
Thread 3 started.
Thread 3 is allocating resources.
[ INFO] kernel:pid[2] tid[3] sys_semaphore_down sem_id = 3
[ INFO] available = [0, 0, 0, 1] ,allocation = [[3, 0, 0, 0], [0, 0, 1, 0], [0, 1, 1, 0], [0, 0, 0, 0]] ,need = [[0, 0, 0, 0], [1, 0, 0, 0], [1, 0, 0, 0], [0, 0, 0, 0]]
[ INFO] kernel:pid[2] tid[3] sys_semaphore_down sem_id = 0
[ INFO] available = [0, 0, 0, 0] ,allocation = [[3, 0, 0, 0], [0, 0, 1, 0], [0, 1, 1, 0], [0, 0, 0, 1]] ,need = [[0, 0, 0, 0], [1, 0, 0, 0], [1, 0, 0, 0], [0, 0, 0, 0]]
[ INFO] work = [0, 0, 0, 0]
[ INFO] process_inner.need[0] = [0, 0, 0, 0]
[ INFO] bigger = true
[ INFO] work = [3, 0, 0, 0]
[ INFO] process_inner.need[1] = [1, 0, 0, 0]
[ INFO] bigger = true
[ INFO] work = [3, 0, 1, 0]
[ INFO] process_inner.need[2] = [1, 0, 0, 0]
[ INFO] bigger = true
[ INFO] work = [3, 1, 2, 0]
[ INFO] process_inner.need[3] = [1, 0, 0, 0]
[ INFO] bigger = true
[ INFO] finish = [true, true, true, true]
[ INFO] We are safe..............
[ INFO] tid[3] gonna sleep
[ INFO] need = [[0, 0, 0, 0], [1, 0, 0, 0], [1, 0, 0, 0], [1, 0, 0, 0]]
Releasing initial semaphores to start threads.
[ INFO] kernel:pid[2] tid[0] sys_semaphore_up, sem_id = 0
[ INFO] available = [1, 0, 0, 0] ,allocation = [[2, 0, 0, 0], [0, 0, 1, 0], [0, 1, 1, 0], [0, 0, 0, 1]] ,need = [[0, 0, 0, 0], [1, 0, 0, 0], [1, 0, 0, 0], [1, 0, 0, 0]]
[ INFO] kernel:pid[2] tid[0] sys_semaphore_up, sem_id = 0
[ INFO] available = [1, 0, 0, 0] ,allocation = [[1, 0, 0, 0], [1, 0, 1, 0], [0, 1, 1, 0], [0, 0, 0, 1]] ,need = [[0, 0, 0, 0], [0, 0, 0, 0], [1, 0, 0, 0], [1, 0, 0, 0]]
[ INFO] kernel:pid[2] tid[0] sys_semaphore_up, sem_id = 0
[ INFO] available = [1, 0, 0, 0] ,allocation = [[0, 0, 0, 0], [1, 0, 1, 0], [1, 1, 1, 0], [0, 0, 0, 1]] ,need = [[0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [1, 0, 0, 0]]
Thread 1 finished initial allocation.
Thread 1 attempting to acquire semaphore 1
[ INFO] kernel:pid[2] tid[1] sys_semaphore_down sem_id = 1
[ INFO] available = [0, 0, 0, 0] ,allocation = [[0, 0, 0, 0], [1, 0, 1, 0], [1, 1, 1, 0], [1, 0, 0, 1]] ,need = [[0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0]]
[ INFO] work = [0, 0, 0, 0]
[ INFO] process_inner.need[0] = [0, 0, 0, 0]
[ INFO] bigger = true
[ INFO] work = [0, 0, 0, 0]
[ INFO] process_inner.need[1] = [0, 1, 0, 0]
[ INFO] bigger = true
[ INFO] work = [1, 0, 1, 0]
[ INFO] process_inner.need[2] = [0, 0, 0, 0]
[ INFO] bigger = true
[ INFO] work = [2, 1, 2, 0]
[ INFO] process_inner.need[3] = [0, 0, 0, 0]
[ INFO] bigger = true
[ INFO] finish = [true, true, true, true]
[ INFO] We are safe..............
[ INFO] tid[1] gonna sleep
[ INFO] need = [[0, 0, 0, 0], [0, 1, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0]]
Thread 2 finished initial allocation.
Thread 2 attempting to acquire semaphore 3
[ INFO] kernel:pid[2] tid[2] sys_semaphore_down sem_id = 3
[ INFO] available = [0, 0, 0, 0] ,allocation = [[0, 0, 0, 0], [1, 0, 1, 0], [1, 1, 1, 0], [1, 0, 0, 1]] ,need = [[0, 0, 0, 0], [0, 1, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0]]
[ INFO] work = [0, 0, 0, 0]
[ INFO] process_inner.need[0] = [0, 0, 0, 0]
[ INFO] bigger = true
[ INFO] work = [0, 0, 0, 0]
[ INFO] process_inner.need[1] = [0, 1, 0, 0]
[ INFO] bigger = true
[ INFO] work = [1, 0, 1, 0]
[ INFO] process_inner.need[2] = [0, 0, 0, 1]
[ INFO] bigger = true
[ INFO] work = [2, 1, 2, 0]
[ INFO] process_inner.need[3] = [0, 0, 0, 0]
[ INFO] bigger = true
[ INFO] finish = [true, true, true, true]
[ INFO] We are safe..............
[ INFO] tid[2] gonna sleep
[ INFO] need = [[0, 0, 0, 0], [0, 1, 0, 0], [0, 0, 0, 1], [0, 0, 0, 0]]
Thread 3 finished initial allocation.
Thread 3 attempting to acquire semaphore 2
[ INFO] kernel:pid[2] tid[3] sys_semaphore_down sem_id = 2
[ INFO] available = [0, 0, 0, 0] ,allocation = [[0, 0, 0, 0], [1, 0, 1, 0], [1, 1, 1, 0], [1, 0, 0, 1]] ,need = [[0, 0, 0, 0], [0, 1, 0, 0], [0, 0, 0, 1], [0, 0, 0, 0]]
[ INFO] work = [0, 0, 0, 0]
[ INFO] process_inner.need[0] = [0, 0, 0, 0]
[ INFO] bigger = true
[ INFO] work = [0, 0, 0, 0]
[ INFO] process_inner.need[1] = [0, 1, 0, 0]
[ INFO] bigger = true
[ INFO] work = [1, 0, 1, 0]
[ INFO] process_inner.need[2] = [0, 0, 0, 1]
[ INFO] bigger = true
[ INFO] work = [2, 1, 2, 0]
[ INFO] process_inner.need[3] = [0, 0, 1, 0]
[ INFO] bigger = true
[ INFO] finish = [true, true, true, true]
[ INFO] We are safe..............
[ INFO] tid[3] gonna sleep
[ INFO] need = [[0, 0, 0, 0], [0, 1, 0, 0], [0, 0, 0, 1], [0, 0, 1, 0]]