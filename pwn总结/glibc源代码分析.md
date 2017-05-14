# glibc源代码分析

### 1. _int_malloc()

_int_malloc()是内存分配的核心，根据分配的内存块的大小，该函数中实现了四种分配内存的路径，分别是fastbin，smallbin，largebin，topchunk(?)。

#### 1.1 分配fast bin chunk

只讨论没有开启ATOMIC_FASTBINS优化的情况，先根据chunk大小计算出chunk所属的fastbin，然后将fastbin链表中的first chunk取出来，如果不为0的话，就返回给用户。为0的话，？？？待定



#### 1.2 分配small bin chunk

如果所需的chunk大小属于small bin，先根据chunk大小计算出chunk所属的small bin，然后将循环链表的最后一项取出来赋值给victim，如果victim与链表头不相等且不为0，则将其从链表中unlink并返回给用户。如果victim与链表头相等，说明链表其实为空。如果victim为0，说明small bin没有初始化，这时候会调用malloc_consolidate函数将fast bins中的chunk合并。这两种情况都需要等待后面的步骤处理。



#### 1.3 之前分配small bin chunk时没有命中 or 要分配large bin chunk

首先根据所需chunk的大小，计算出chunk所属的large bin的index，然后判断当前分配区的fast bins中是否包含chunk，如果存在就调用malloc_consolidate函数进行合并，并将这些空闲chunk加入unsorted bin中。

基于以下的假设

```C
/* If this is a large request, consolidate fastbins before continuing. While it might look excessive to kill all fastbins before even seeing if there is space available, this avoids fragmentation problems normally associated with fastbins. Also, in practice, programs tend to have runs of either small or large requests, but less often mixtures, so consolidation is not invoked all that often in most programs. And the programs that it is called frequently in otherwise tend to fragment. */
```



然后开始反向遍历unsorted bin的双向循环链表，遍历结束的条件是循环链表中只剩下一个头结点。

遍历的过程中如果需要分配一个small bin chunk，如果unsorted bin中只有一个

chunk，而且这个chunk是last remainder chunk，而且这个chunk大小足够，那么可以用这个chunk切分出想要的chunk，然后将剩下的chunk加入unsorted bin的链表中，并将剩下的chunk作为分配区的last remainder chunk，然后返回应用层，退出。

如果不符合以上的条件，遍历的过程中先讲unsorted bin中的最后一个chunk unlink出来。如果size和用户所需的chunk大小一致，那么就返回给用户，然后退出。如果不一致，那么要么放到small bin中，要么放到large bin中。



> large bin中的chunk是按照从大到小的顺序排序的，同时一个chunk存在于两个双向循环链表中，一个链表包含了large bin中所有的chunk，另一个链表为chunk size链表，该链表从每个相同大小的chunk的取出第一个chunk按照大小顺序链接在一起，便于一次跨域多个相同大小的chunk遍历下一个不同大小的chunk，这样可以加快在large bin链表中的遍历速度。 

如果unsorted bin中的chunk超过了10000个，最多遍历10000个就退出，避免长时间处理unsorted bin影响内存分配的效率。 

当unsorted bin中的空闲chunk加入到相应的small bins和large bins之后，将使用best fit匹配法分配large bin chunk。反向遍历chunk size链表，直到找到第一个大于等于所需chunk大小的chunk退出循环。如果产生了切分，切分出的chunk加入unsorted bin中。

上述方法是从最合适的small bin或者large bin中找chunk，如果仍然没有找到。那么查看比当前bin的index大的small bin或者large bin是否有空闲的chunk可以利用。



#### 1.4 top chunk分配内存

如果从所有的bins中都没有获得所需的chunk，可能的情况是bins中没有空闲的chunk，或者所需的chunk大小很大，下一步尝试从top chunk中分配chunk。

如果top chunk也不能满足需求，查看fast bins中是否有空闲chunk存在，如果有，有开启ATOMIC_FASTBINS优化的情况下，只有一种可能，那就是所需的chunk属于small bins，但通过前面的步骤都没有分配到所需的small bin chunk，由于分配small bin chunk时在前面的步骤都不会调用malloc_consolidate()函数将fast bins中的空闲chunk合并加入到unsorted bin中。所以这里如果有空闲chunk存在，那么调用malloc_consolidata函数将fast bin中的chunk合并加入到unsorted bin中，并跳转到最外层的循环，尝试重新分配small bin chunk。



#### 1.5 向系统申请内存

先只讨论main arena的情况。如果所需分配的内存大于 mmap 分配阈值，默认为128k，并且当前进程使用 mmap 分配的内存块小于设定的最大值，将使用 mmap 向系统分配内存。

如果不使用 mmap 分配内存，那就需要扩展 top chunk 的大小，如果当前 arena 是连续的，那么就使用 sbrk 来扩展堆的地址空间，如果 sbrk 返回失败或者 sbrk 不可用，使用 mmap 代替，重新计算所需分配的内存大小（这时候就不用利用已有的 top chunk 的空间了，因为不连续）

#### 1.6 malloc_consolidate

malloc_consolidata 函数用于将 fastbin 中的 chunk 合并，并加入 unsorted bin 当中。很简单，不多介绍



#### 1.7 public_fREe

如果存在 free 的 hook 函数，那么就执行 hook 函数返回。如果 free 函数的参数为0，那么什么都不做直接返回。如果 free 的 chunk 是 mmaped 的，那么调用 munmap_chunk 函数。如果开启了分配阈值动态调整机制，那么还需要修改mmap 的分配阈值和收缩阈值。

如果没有开启ATOMIC_FASTBINS 优化，获取arena的锁，调用_int_free()函数执行实际的释放工作，然后对分配区解锁



#### 1.8 _int_free()

如果当前 free 的 chunk 属于 fast bins，会 首先检查下一个相邻的 chunk 大小是否小于等于2*SIZE_SZ（一个 chunk 的最小的大小）， 下一个相邻 chunk 的大小是否大于分配区所分配的内存总量，如果是，报错。这里的逻辑是如果按道理下一个 chunk 的 prev_inuse 标志位会置位，如果等于2\*SIZE_SZ，也就是没有置位，说明出错了。



