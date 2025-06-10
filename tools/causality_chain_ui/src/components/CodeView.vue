<script setup>
import 'highlight.js/styles/github.css';
import { ref, computed, nextTick, onMounted, watch } from 'vue';
import CodeItem from "@/components/CodeItem.vue"

const props = defineProps({
  id: {
    type: String,
    required: true
  },
  codeItems: {
    type: Array,
    required: true
  }
})
let codeBoxHeight = ref(0);
let inline = [];
watch(
  () => props.codeItems,
  (newValue, oldValue) => {
    if (newValue !== oldValue) {
      codeBoxHeight = 80 / props.codeItems.length - 1;
    }
    const total = props.codeItems.length;
    inline = [];
    for (let i = 0; i < total; i++) {
      let hint = '';
      if (i === 0) {
        hint = `Inline Level ${i} (inner)`;
      }
      else if (i === total - 1) {
        hint = `Inline Level ${i} (outer)`;
      }
      else {
        hint = `Inline Level ${i}`;
      }
      inline.push(hint);
    }
  },
  { deep: true }
);

</script>

<template>
  <div style="position: relative;display: flex;flex-direction: column;max-height: 80vh;overflow: hidden">
    <div v-for="(codeItem, index) in props.codeItems">
      <CodeItem :key="index" :id="`code-${props.id}-${index}`" :inlineLevel="`${inline[index]}`" :sourceCode="codeItem"
        :codeBoxHeight="codeBoxHeight" :index="index" />
    </div>
  </div>
</template>
